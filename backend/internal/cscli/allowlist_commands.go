package cscli

func optionalField(fields map[string]string, fieldName string, validate validator) (string, bool, error) {
	if _, present := fields[fieldName]; !present {
		return "", false, nil
	}
	value, validationError := validatedField(fields, fieldName, validate)
	if validationError != nil {
		return "", false, validationError
	}
	return value, true, nil
}

func buildAllowlistsCreate(fields map[string]string) ([]string, error) {
	if err := exactFields(fields, "name", "description"); err != nil {
		return nil, err
	}
	name, nameError := validatedField(fields, "name", validateAllowlistName)
	if nameError != nil {
		return nil, nameError
	}
	description, descriptionError := validatedField(fields, "description", validateFreeText)
	if descriptionError != nil {
		return nil, descriptionError
	}
	return []string{"cscli", "allowlists", "create", name, "--description=" + description}, nil
}

func buildAllowlistsDelete(fields map[string]string) ([]string, error) {
	return withName(validateAllowlistName, []string{"cscli", "allowlists", "delete"})(fields)
}

func buildAllowlistsAdd(fields map[string]string) ([]string, error) {
	if err := exactFields(fields, "name", "value", "expiration", "comment"); err != nil {
		return nil, err
	}
	name, nameError := validatedField(fields, "name", validateAllowlistName)
	if nameError != nil {
		return nil, nameError
	}
	value, valueError := validatedField(fields, "value", validateAllowlistValue)
	if valueError != nil {
		return nil, valueError
	}
	expiration, hasExpiration, expirationError := optionalField(fields, "expiration", validateAllowlistExpiration)
	if expirationError != nil {
		return nil, expirationError
	}
	comment, hasComment, commentError := optionalField(fields, "comment", validateFreeText)
	if commentError != nil {
		return nil, commentError
	}
	argv := []string{"cscli", "allowlists", "add", name, value}
	if hasExpiration {
		argv = append(argv, "--expiration="+expiration)
	}
	if hasComment {
		argv = append(argv, "--comment="+comment)
	}
	return argv, nil
}

func buildAllowlistsRemove(fields map[string]string) ([]string, error) {
	if err := exactFields(fields, "name", "value"); err != nil {
		return nil, err
	}
	name, nameError := validatedField(fields, "name", validateAllowlistName)
	if nameError != nil {
		return nil, nameError
	}
	value, valueError := validatedField(fields, "value", validateAllowlistValue)
	if valueError != nil {
		return nil, valueError
	}
	return []string{"cscli", "allowlists", "remove", name, value}, nil
}
