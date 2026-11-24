
import ipaddress


MAX_CIDR_ADDRESSES = 65536


def validate_ip(value: str) -> str:
    """Validate a single IPv4 address."""

    value = value.strip()

    if not value:
        raise ValueError("IP address cannot be empty.")

    try:
        address = ipaddress.IPv4Address(value)

    except ValueError as error:
        raise ValueError(
            f"Invalid IPv4 address: {value}"
        ) from error

    return str(address)



def validate_cidr(value: str) -> str:
    """Validate an IPv4 CIDR network and enforce its size limit."""

    value = value.strip()

    if not value:
        raise ValueError("CIDR range cannot be empty.")

    try:
        network = ipaddress.IPv4Network(value, strict=False)

    except ValueError as error:
        raise ValueError(
            f"Invalid IPv4 CIDR range: {value}"
        ) from error

    if network.num_addresses > MAX_CIDR_ADDRESSES:
        raise ValueError(
            f"CIDR range is too large. "
            f"Maximum allowed size is {MAX_CIDR_ADDRESSES} addresses."
        )

    return str(network)



def validate_ip_list(values: list[str]) -> tuple[list[str], list[str]]:
    """Validate multiple IPv4 addresses."""

    valid_ips = []
    invalid_ips = []

    for value in values:
        try:
            valid_ips.append(validate_ip(value))

        except ValueError as error:
            invalid_ips.append(str(error))

    return valid_ips, invalid_ips


def get_scope_warnings(target: str) -> list[str]:
    """Identify public and loopback targets."""

    warnings = []

    if "/" in target:
        address = ipaddress.IPv4Network(target, strict=True)
    else:
        address = ipaddress.IPv4Address(target)

    if address.is_loopback:
        warnings.append(
            "Loopback address detected. "
            "This target refers to the local machine."
        )

    elif address.is_global:
        warnings.append(
            "Public IP address detected. "
            "Ensure you have authorization before proceeding."
        )

    return warnings
