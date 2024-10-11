def create_scanner(gmp, scan_name, credentialID, hostToScan, portToScan):
    scanner_response = gmp.create_scanner(name=scan_name, host=hostToScan, port=portToScan, credential_id=credentialID, scanner_type=gmp.types.ScannerType.OPENVAS_SCANNER_TYPE)
    if scanner_response.get('status') in ["200", "201"]:
        return scanner_response.get('id')
    elif scanner_response.get('status') != "200" and scanner_response.get('status_text') == "Scanner exists already":
        scanners = gmp.get_scanners()
        for scanner in scanners:
            scannerID = scanner.get('id')
            scannerNames = scanner.findall('.//name')
            for scannerName in scannerNames:
                if scannerName.text == scan_name:
                    return scannerID
    else:
        raise Exception(f"Error creation scanner: {scanner_response.get('status_text')}")
