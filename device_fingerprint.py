def create_fingerprint(device):
    fingerprint = {
        "vendor_id": device.get("VendorID"),
        "product_id": device.get("ProductID"),
        "serial": device.get("SerialNumber"),
        "vendor": device.get("Manufacturer"),
        "model": device.get("Product"),
    }
    return fingerprint
