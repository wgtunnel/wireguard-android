@file:Suppress("UnstableApiUsage")

import org.gradle.api.tasks.testing.logging.TestLogEvent

val pkg: String = providers.gradleProperty("wireguardPackageName").get()

plugins {
    alias(libs.plugins.android.library)
    `maven-publish`
    signing
}

android {
    compileSdk = 36
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    namespace = "${pkg}.tunnel"
    defaultConfig {
        minSdk = 21
    }
    externalNativeBuild {
        cmake {
            path("tools/CMakeLists.txt")
        }
    }
    testOptions.unitTests.all {
        it.testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
    }
    buildTypes {
        all {
            externalNativeBuild {
                cmake {
                    targets("libwg-go.so", "libwg.so", "libwg-quick.so")
                    arguments("-DGRADLE_USER_HOME=${project.gradle.gradleUserHomeDir}")
                    arguments("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON")
                }
            }
        }
        release {
            externalNativeBuild {
                cmake {
                    arguments("-DANDROID_PACKAGE_NAME=${pkg}")
                }
            }
        }
        debug {
            externalNativeBuild {
                cmake {
                    arguments("-DANDROID_PACKAGE_NAME=${pkg}.debug")
                }
            }
        }
    }
    lint {
        disable += "LongLogTag"
        disable += "NewApi"
    }
    publishing {
        singleVariant("release") {
            withJavadocJar()
            withSourcesJar()
        }
    }
}

dependencies {
    implementation(libs.androidx.annotation)
    implementation(libs.androidx.collection)
    compileOnly(libs.jsr305)
    testImplementation(libs.junit)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.zaneschepke"
            artifactId = "wireguard-android"
            version = providers.gradleProperty("wireguardVersionName").get()
            afterEvaluate {
                from(components["release"])
            }
            pom {
                name.set("WireGuard Tunnel Library")
                description.set("Embeddable tunnel library for WireGuard for Android")
                url.set("https://www.wireguard.com/")

                licenses {
                    license {
                        name.set("The Apache Software License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/zaneschepke/wireguard-android")
                    developerConnection.set("scm:git:https://github.com/zaneschepke/wireguard-android")
                    url.set("https://github.com/zaneschepke/wireguard-android")
                }
                developers {
                    organization {
                        name.set("Zane Schepke")
                        url.set("https://zaneschepke.com")
                    }
                    developer {
                        name.set("Zane Schepke")
                        email.set("support@zaneschepke.com")
                    }
                }
            }
        }
    }
}

signing {
    extra["signing.keyId"] = getLocalProperty("KEY_ID")
    extra["signing.secretKeyRingFile"] = getLocalProperty("SECRET_KEY_RING_FILE")
    extra["signing.password"] = getLocalProperty("PASSWORD")
    sign(publishing.publications)
}
