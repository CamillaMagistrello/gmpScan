def create_target(gmp, hostToScan, nameTarget):
    target_response = gmp.create_target(name=nameTarget, hosts=hostToScan)
    if target_response.get('status') in ["200", "201"]:
        return target_response.get('id')
    elif target_response.get('status') != "200" and target_response.get('status_text') == "Target exists already":
        targetList = gmp.get_targets()
        for target in targetList:
            targetID = target.get('id')
            targetNames = target.findall('.//name')
            for taegetName in targetNames:
                if taegetName.text == nameTarget:
                    return targetID
    else:
        raise Exception(f"Error creation target: {target_response.get('status_text')}")
