package secrets

import (
	"strconv"

	"crowdsec-dashboard/internal/netparse"
)

const (
	machinePasswordLabel = "engine.machine_password"
	proxyCredentialLabel = "engine.proxy_credential"
	sidecarKeyLabel      = "engine.sidecar_signing_key"
)

func EngineSidecarKeyAssociatedData(engineID int64, sidecarURL, keyID string) []byte {
	return engineSidecarKeyAssociatedData(strconv.FormatInt(engineID, 10), sidecarURL, keyID)
}

func engineSidecarKeyAssociatedData(engineIDText, sidecarURL, keyID string) []byte {
	return []byte(sidecarKeyLabel + ":" + engineIDText + lengthPrefixed(netparse.DestinationKey(sidecarURL)) + lengthPrefixed(keyID))
}

func EngineMachinePasswordAssociatedData(engineID int64, lapiURL string) []byte {
	return engineMachinePasswordAssociatedData(strconv.FormatInt(engineID, 10), lapiURL)
}

func EngineProxyCredentialAssociatedData(engineID int64, lapiURL, proxyKind, proxyURL string) []byte {
	return engineProxyCredentialAssociatedData(strconv.FormatInt(engineID, 10), lapiURL, proxyKind, proxyURL)
}

func LegacyEngineMachinePasswordAssociatedData(engineID int64) []byte {
	return []byte(machinePasswordLabel + ":" + strconv.FormatInt(engineID, 10))
}

func LegacyEngineProxyCredentialAssociatedData(engineID int64) []byte {
	return []byte(proxyCredentialLabel + ":" + strconv.FormatInt(engineID, 10))
}

func engineMachinePasswordAssociatedData(engineIDText, lapiURL string) []byte {
	return []byte(machinePasswordLabel + ":" + engineIDText + ":" + netparse.DestinationKey(lapiURL))
}

func engineProxyCredentialAssociatedData(engineIDText, lapiURL, proxyKind, proxyURL string) []byte {
	return []byte(proxyCredentialLabel + ":" + engineIDText +
		lengthPrefixed(netparse.DestinationKey(lapiURL)) + lengthPrefixed(proxyKind) + lengthPrefixed(proxyURL))
}

func lengthPrefixed(part string) string {
	return ":" + strconv.Itoa(len(part)) + ":" + part
}
