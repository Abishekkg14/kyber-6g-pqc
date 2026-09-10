set(source_files
    model/pqc-session-keys.cc
    model/hardware-profile.cc
    model/pqc-key-cache.cc
    model/pqc-energy-model.cc
    model/crystals-kyber-kem.cc
    model/x25519-ecdh.cc
    model/hybrid-kem-combiner.cc
    model/ml-dsa-signer.cc
    model/aes-gcm-cipher.cc
    model/pqc-pdcp-layer.cc
    model/pqc-rrc-extension.cc
    model/pqc-handover-manager.cc
    model/quantum-attacker.cc
    model/pqc-metrics-collector.cc
    model/pqc-drone-app.cc
    model/pqc-adaptive-key-manager.cc
    model/thz-gilbert-elliott-channel.cc
    model/mg1-queue-tracker.cc
    model/raptor-fountain-coder.cc
    model/snc-queue-tracker.cc
    helper/pqc-security-helper.cc
    helper/pqc-scenario-helper.cc
)

set(header_files
    model/pqc-session-keys.h
    model/hardware-profile.h
    model/pqc-key-cache.h
    model/pqc-energy-model.h
    model/crystals-kyber-kem.h
    model/x25519-ecdh.h
    model/hybrid-kem-combiner.h
    model/ml-dsa-signer.h
    model/aes-gcm-cipher.h
    model/pqc-pdcp-layer.h
    model/pqc-rrc-extension.h
    model/pqc-handover-manager.h
    model/quantum-attacker.h
    model/pqc-metrics-collector.h
    model/pqc-drone-app.h
    model/pqc-adaptive-key-manager.h
    model/thz-gilbert-elliott-channel.h
    model/mg1-queue-tracker.h
    model/raptor-fountain-coder.h
    model/snc-queue-tracker.h
    helper/pqc-security-helper.h
    helper/pqc-scenario-helper.h
)

set(test_sources
    test/pqc-security-test-suite.cc
)

build_lib(
    LIBNAME pqc-security
    SOURCE_FILES ${source_files}
    HEADER_FILES ${header_files}
    LIBRARIES_TO_LINK
        ${libcore}
        ${libnetwork}
        ${libinternet}
        ${libapplications}
        ${liblte}
        ${libnr}
        ${libflow-monitor}
        ${libmobility}
    TEST_SOURCES ${test_sources}
)
