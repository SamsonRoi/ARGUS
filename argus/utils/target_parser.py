
from argus.utils.validators import (
    validate_ip,
    validate_cidr,
)


def parse_targets(
    target_type: str,
    raw_input: str,
) -> tuple[list[str], list[str]]:
    """
    Parse raw target input and return valid and invalid targets.

    Returns:
        A tuple containing:
        - List of valid, normalized targets.
        - List of invalid targets with error messages.
    """

    valid_targets = []
    invalid_targets = []

    target_type = target_type.strip().lower()

    # Handle a single IP address.
    if target_type == "single ip":

        try:
            valid_targets.append(validate_ip(raw_input))

        except ValueError as error:
            invalid_targets.append(str(error))

    # Handle a CIDR network.
    elif target_type == "cidr range":

        try:
            valid_targets.append(validate_cidr(raw_input))

        except ValueError as error:
            invalid_targets.append(str(error))

    # Handle multiple comma-separated IP addresses.
    elif target_type == "multiple ips":

        raw_targets = raw_input.split(",")

        seen_targets = set()

        for raw_target in raw_targets:

            try:
                target = validate_ip(raw_target)

                if target not in seen_targets:
                    valid_targets.append(target)
                    seen_targets.add(target)

            except ValueError as error:
                invalid_targets.append(str(error))

    else:
        raise ValueError(
            f"Unsupported target type: {target_type}"
        )

    return valid_targets, invalid_targets
