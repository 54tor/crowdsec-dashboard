package allowlists

import (
	"context"
	"net/netip"

	"crowdsec-dashboard/internal/lapi"
)

func (service *Service) Create(ctx context.Context, engineName, allowlistName, description string) (MutationResult, error) {
	target, prepareError := service.prepareWrite(ctx, engineName)
	if prepareError != nil {
		return MutationResult{}, prepareError
	}
	if _, exists := findAllowlist(target.read, allowlistName); exists {
		return MutationResult{}, ErrAllowlistExists
	}
	if writeError := target.writer.Create(ctx, allowlistName, description); writeError != nil {
		return MutationResult{}, writeError
	}
	return service.confirmWrite(ctx, target, func(read lapi.AllowlistRead) bool {
		_, created := findAllowlist(read, allowlistName)
		return created
	})
}

func (service *Service) Delete(ctx context.Context, engineName, allowlistName string) (MutationResult, error) {
	target, prepareError := service.prepareWrite(ctx, engineName)
	if prepareError != nil {
		return MutationResult{}, prepareError
	}
	if _, allowlistError := writableAllowlist(target.read, allowlistName); allowlistError != nil {
		return MutationResult{}, allowlistError
	}
	if writeError := target.writer.Delete(ctx, allowlistName); writeError != nil {
		return MutationResult{}, writeError
	}
	return service.confirmWrite(ctx, target, func(read lapi.AllowlistRead) bool {
		_, stillPresent := findAllowlist(read, allowlistName)
		return !stillPresent
	})
}

func (service *Service) AddEntry(ctx context.Context, engineName, allowlistName string, entry EntryInput) (MutationResult, error) {
	target, prepareError := service.prepareWrite(ctx, engineName)
	if prepareError != nil {
		return MutationResult{}, prepareError
	}
	allowlist, allowlistError := writableAllowlist(target.read, allowlistName)
	if allowlistError != nil {
		return MutationResult{}, allowlistError
	}
	value, valueError := validateNewEntry(entry)
	if valueError != nil {
		return MutationResult{}, valueError
	}
	if containsValue(allowlist, value) {
		return MutationResult{}, ErrEntryExists
	}
	if writeError := target.writer.Add(ctx, allowlistName, value, entry.Expiration, entry.Description); writeError != nil {
		return MutationResult{}, writeError
	}
	return service.confirmWrite(ctx, target, entryPresence(allowlistName, value, true))
}

func (service *Service) RemoveEntry(ctx context.Context, engineName, allowlistName, rawValue string) (MutationResult, error) {
	target, prepareError := service.prepareWrite(ctx, engineName)
	if prepareError != nil {
		return MutationResult{}, prepareError
	}
	allowlist, allowlistError := writableAllowlist(target.read, allowlistName)
	if allowlistError != nil {
		return MutationResult{}, allowlistError
	}
	value, valueError := parseValue(rawValue)
	if valueError != nil {
		return MutationResult{}, valueError
	}
	isProvenAbsent := !target.read.Truncated && !containsValue(allowlist, value)
	if isProvenAbsent {
		return MutationResult{}, ErrEntryNotFound
	}
	if writeError := target.writer.Remove(ctx, allowlistName, value); writeError != nil {
		return MutationResult{}, writeError
	}
	return service.confirmWrite(ctx, target, entryPresence(allowlistName, value, false))
}

func entryPresence(allowlistName string, value netip.Prefix, expectedPresent bool) changeCheck {
	return func(read lapi.AllowlistRead) bool {
		allowlist, found := findAllowlist(read, allowlistName)
		isPresent := found && containsValue(allowlist, value)
		return isPresent == expectedPresent
	}
}
