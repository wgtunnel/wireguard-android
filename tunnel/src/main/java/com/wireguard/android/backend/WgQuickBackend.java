/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.content.Context;
import android.util.Log;
import android.util.Pair;

import com.wireguard.android.backend.BackendException.Reason;
import com.wireguard.android.backend.Tunnel.State;
import com.wireguard.android.util.RootShell;
import com.wireguard.android.util.ToolsInstaller;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.util.NonNullForAll;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

import androidx.annotation.Nullable;

/**
 * Implementation of {@link Backend} that uses the kernel module and {@code wg-quick} to provide
 * WireGuard tunnels.
 */

@NonNullForAll
public final class WgQuickBackend implements Backend {
    private static final Pattern PATTERN = Pattern.compile("\\t");
    private static final String TAG = "WireGuard/WgQuickBackend";
    private static final int DNS_RESOLUTION_RETRIES = 3;
    private final File localTemporaryDir;
    private final RootShell rootShell;
    private final Map<Tunnel, Config> runningConfigs = new HashMap<>();
    private final ToolsInstaller toolsInstaller;
    private boolean multipleTunnels;
    private final TunnelActionHandler tunnelActionHandler;


    public WgQuickBackend(final Context context, final RootShell rootShell, final ToolsInstaller toolsInstaller, final TunnelActionHandler tunnelActionHandler) {
        localTemporaryDir = new File(context.getCacheDir(), "tmp");
        this.rootShell = rootShell;
        this.toolsInstaller = toolsInstaller;
        this.tunnelActionHandler = tunnelActionHandler;
    }

    public static boolean hasKernelSupport() {
        return new File("/sys/module/wireguard").exists();
    }

    @Override
    public Set<String> getRunningTunnelNames() {
        final List<String> output = new ArrayList<>();
        // Don't throw an exception here or nothing will show up in the UI.
        try {
            toolsInstaller.ensureToolsAvailable();
            if (rootShell.run(output, "wg show interfaces") != 0 || output.isEmpty())
                return Collections.emptySet();
        } catch (final Exception e) {
            Log.w(TAG, "Unable to enumerate running tunnels", e);
            return Collections.emptySet();
        }
        // wg puts all interface names on the same line. Split them into separate elements.
        return Set.of(output.get(0).split(" "));
    }

    @Override
    public State getState(final Tunnel tunnel) {
        return getRunningTunnelNames().contains(tunnel.getName()) ? State.UP : State.DOWN;
    }

    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        final Collection<String> output = new ArrayList<>();
        try {
            if (rootShell.run(output, String.format("wg show '%s' dump", tunnel.getName())) != 0)
                return stats;
        } catch (final Exception ignored) {
            return stats;
        }
        for (final String line : output) {
            final String[] parts = PATTERN.split(line);
            if (parts.length != 8)
                continue;
            try {
                stats.add(Key.fromBase64(parts[0]),  parts[2], Long.parseLong(parts[5]), Long.parseLong(parts[6]), Long.parseLong(parts[4]) * 1000);
            } catch (final Exception ignored) {
            }
        }
        return stats;
    }

    @Override
    public String getVersion() throws Exception {
        final List<String> output = new ArrayList<>();
        if (rootShell.run(output, "cat /sys/module/wireguard/version") != 0 || output.isEmpty())
            throw new BackendException(Reason.UNKNOWN_KERNEL_MODULE_NAME);
        return output.get(0);
    }

    public void setMultipleTunnels(final boolean on) {
        multipleTunnels = on;
    }

    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);
        final Config originalConfig = runningConfigs.get(tunnel);
        final Map<Tunnel, Config> runningConfigsSnapshot = new HashMap<>(runningConfigs);
        if ((state == State.UP && originalState == State.UP && originalConfig != null && originalConfig == config) ||
                (state == State.DOWN && originalState == State.DOWN))
            return originalState;
        if (state == State.UP) {
            toolsInstaller.ensureToolsAvailable();
            if (!multipleTunnels && originalState == State.DOWN) {
                final List<Pair<Tunnel, Config>> rewind = new LinkedList<>();
                try {
                    for (final Map.Entry<Tunnel, Config> entry : runningConfigsSnapshot.entrySet()) {
                        setStateInternal(entry.getKey(), entry.getValue(), State.DOWN);
                        rewind.add(Pair.create(entry.getKey(), entry.getValue()));
                    }
                } catch (final Exception e) {
                    try {
                        for (final Pair<Tunnel, Config> entry : rewind) {
                            setStateInternal(entry.first, entry.second, State.UP);
                        }
                    } catch (final Exception ignored) {
                    }
                    throw e;
                }
            }
            if (originalState == State.UP)
                setStateInternal(tunnel, originalConfig == null ? config : originalConfig, State.DOWN);
            try {
                setStateInternal(tunnel, config, State.UP);
            } catch (final Exception e) {
                try {
                    if (originalState == State.UP && originalConfig != null) {
                        setStateInternal(tunnel, originalConfig, State.UP);
                    }
                    if (!multipleTunnels && originalState == State.DOWN) {
                        for (final Map.Entry<Tunnel, Config> entry : runningConfigsSnapshot.entrySet()) {
                            setStateInternal(entry.getKey(), entry.getValue(), State.UP);
                        }
                    }
                } catch (final Exception ignored) {
                }
                throw e;
            }
        } else if (state == State.DOWN) {
            setStateInternal(tunnel, originalConfig == null ? config : originalConfig, State.DOWN);
        }
        return state;
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state) throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        Objects.requireNonNull(config, "Trying to set state up with a null config");

        if(state == State.UP) {
            List<InetEndpoint> failedEndpoints = new ArrayList<>();
            for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
                failedEndpoints.clear();
                for (final Peer peer : config.getPeers()) {
                    Optional<InetEndpoint> epOpt = peer.getEndpoint();
                    if (epOpt.isEmpty()) continue;
                    InetEndpoint ep = epOpt.get();
                    if (ep.getResolved(tunnel.isIpv4ResolutionPreferred()).isEmpty()) {
                        failedEndpoints.add(ep);
                    }
                }
                if (failedEndpoints.isEmpty()) break;
                if (i < DNS_RESOLUTION_RETRIES - 1) {
                    for (InetEndpoint ep : failedEndpoints) {
                        Log.w(TAG, "DNS host \"" + ep.getHost() + "\" failed (attempt " + (i + 1) + " of " + DNS_RESOLUTION_RETRIES + ')');
                    }
                    try {
                        Thread.sleep(500L * (1 << i));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, "Interrupted during DNS retry");
                    }
                } else {
                    throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, failedEndpoints.get(0).getHost());
                }
            }
        }

        final File tempFile = new File(localTemporaryDir, tunnel.getName() + ".conf");
        try (final FileOutputStream stream = new FileOutputStream(tempFile, false)) {
            final String conf = config.toResolvedWgQuickString(false, tunnel.isIpv4ResolutionPreferred());
            stream.write(conf.getBytes(StandardCharsets.UTF_8));
        }
        String command = String.format("wg-quick %s '%s'",
                state.toString().toLowerCase(Locale.ENGLISH), tempFile.getAbsolutePath());
        if (state == State.UP) {
            command = "cat /sys/module/wireguard/version && " + command;
            tunnelActionHandler.runPreUp(config.getInterface().getPreUp());
        } else {
            tunnelActionHandler.runPreDown(config.getInterface().getPreDown());
        }
        final int result = rootShell.run(null, command);
        if(state == State.UP) {
            tunnelActionHandler.runPostUp(config.getInterface().getPostUp());
        } else {
            tunnelActionHandler.runPostDown(config.getInterface().getPostDown());
        }
        // noinspection ResultOfMethodCallIgnored
        tempFile.delete();
        if (result != 0)
            throw new BackendException(Reason.WG_QUICK_CONFIG_ERROR_CODE, result);

        if (state == State.UP)
            runningConfigs.put(tunnel, config);
        else
            runningConfigs.remove(tunnel);

        tunnel.onStateChange(state);
    }
}
