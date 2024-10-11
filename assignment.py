from flask import Flask, jsonify, request
from gvm.errors import GvmError
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
import gmpScan


app = Flask(__name__)
host = 'openvas'
port = 9390
username = 'admin'
password = 'admin'
pathToCertificate = './gmpScan/Utility/Certificate/'
CLIENT_CERTIFICATE = pathToCertificate + 'client.pem'
CLIENT_PRIVATE_KEY = pathToCertificate + 'client.key'
configName = gmpScan.EnumConfigurationTasks.FULL_AND_FAST.value
SCAN_NAME = "OpenVAS Default"

@app.route('/createScan', methods=['POST'])
def create_scan():
    try:
        connection = TLSConnection(hostname=host, port=port, timeout=300)
        transform = EtreeTransform()
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(username, password)
            credentialID = gmpScan.create_credential(gmp, username, password, CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)
            data = request.get_json()
            scan_name = data['scan_name']
            targets = data['targets']
            output = {
                "scan_name": scan_name,
                "targets": targets,
                "result_details": [],
                "result_summary": []
            }
            for target in targets:
                app.logger.info(f"Start scan of: {target}")
                portToScan = None
                hostToScan = None
                if target.startswith('http://'):
                    target = target.replace('http://', '') 
                if ":" in target:
                    tmp = target.split(":")
                    portToScan = tmp[1]
                    hostToScan = tmp[0]
                else:
                    hostToScan = target
                    portToScan = 8080
                if hostToScan == 'localhost':
                    hostToScan = '127.0.0.1'
                app.logger.info(f"portToScan: {portToScan}, hostToScan: {hostToScan}")
                listOfHosts = []
                listOfHosts.append(hostToScan)
                
                scannerID = gmpScan.create_scanner(gmp, SCAN_NAME, credentialID, hostToScan, portToScan)
                app.logger.info(f"Scanner created with id: {scannerID}")

                nameTarget = "Target: " + str(hostToScan)
                targetID = gmpScan.create_target(gmp, listOfHosts, nameTarget)
                app.logger.info(f"Target created with id: {targetID}")

                configs_response = gmp.get_configs()
                config_id = getConfigId(configs_response)
                if config_id:
                    taskID = gmpScan.create_task(gmp, scannerID, targetID, config_id, host=hostToScan)
                    app.logger.info(f"Task created with id: {taskID}")
                else:
                    app.logger.error("Error get configuration ID")
                    return jsonify({'error': 'Error get configuration ID'}), 500

                app.logger.info("START TASK")
                gmpScan.startTask(gmp, taskID)
                app.logger.info("Finish scan task")
                reportID = gmpScan.get_report_id(gmp, taskID, targetID)
                app.logger.info(f"Report id: {reportID}")
                
                reportFind = gmp.get_report(report_id=reportID, details=True, report_format_id=gmp.types.ReportFormatType.XML.value, filter='levels=hml')
                if reportFind is not None:
                    reportFound = reportFind.find('report')
                    if reportFound is not None:
                        report = reportFound.find('report')
                        if report is not None:
                            results = report.find('results')

                            if results is not None:
                                listOfResults = []
                                listOfResults = results.findall('result')
                                if listOfResults is not None:
                                    currentSeverity = 0
                                    severityMax = 0
                                    result = None
                                    cveFound = None
                                    nvtFound = None
                                    nvt = None
                                    cve = None
                                    for currentResult in listOfResults:
                                        currentSeverity = currentResult.find('severity').text
                                        nvt = currentResult.find('nvt')
                                        cve = nvt.find('cve').text
                                        if float(currentSeverity) > float(severityMax) and cve != 'NOCVE':
                                            severityMax = currentSeverity
                                            result = currentResult
                                            cveFound = cve
                                            nvtFound = nvt
                                        
                                    if cveFound is None:
                                        cveFound = 'NOCVE'
                                        for currentResult in listOfResults:
                                            currentSeverity = currentResult.find('severity').text
                                            if float(currentSeverity) > float(severityMax):
                                                nvtFound = currentResult.find('nvt')
                                                severityMax = currentSeverity
                                                result = currentResult

                                    currentSeverity = result.find('severity').text
                                    endpoint = hostToScan + ":" + portToScan
                                    object_details = {
                                        "endpoint": endpoint,
                                        "score": currentSeverity,
                                        "cves": cveFound
                                    }
                                    if "," in cveFound:
                                        cveFound = cveFound.split(',')[0]
                                    object_summary = {
                                        "endpoint": endpoint,
                                        "score": currentSeverity,
                                        "cve": cveFound
                                    }
                                
                                    tags = nvtFound.find('tags').text
                                    cvssTag = tags.split('|')[0]
                                    cvssBaseVector = cvssTag.split('/')
                                    baseMetrics = None
                                    value = None
                                    for cvss in cvssBaseVector:
                                        if "cvss_base_vector=" in cvss:
                                            cvss = cvss.replace('cvss_base_vector=', '')
                                        tmp = cvss.split(':')
                                        baseMetrics = tmp[0]
                                        value = tmp[1]
                                        object_summary[baseMetrics] = value

                                    for indx, tag in enumerate(tags.split('|')):
                                        if(indx != 0):
                                            if('=' in tag):
                                                name = tag.split("=")[0]
                                                value = tag.split("=")[1]
                                                object_details[name] = value

                                    output["result_summary"].append(object_summary)
                                    output["result_details"].append(object_details)
                                else:
                                    app.logger.error("Result element not found in the results.")
                                    return jsonify({'error': 'Result element not found in the results'}), 500
                            else:
                                app.logger.error("Results element not found in the report.")
                                return jsonify({'error': 'Results element not found in the report'}), 500
                        else:
                            app.logger.error("Report element not found in the report.")
                            return jsonify({'error': 'Report element not found in the report'}), 500
                    else:
                        app.logger.error("Report element not found in the report.")
                        return jsonify({'error': 'Report element not found in the report'}), 500
                else:
                    app.logger.error(f"Report not found for the given report ID: {reportID}")
                    return jsonify({'error': 'Report not found for the given report ID'}), 500
            return output

    except GvmError as e:
        app.logger.error(f"GVM Error: {str(e)}")
        return jsonify({'error': 'An error occurred while communicating with GVM'}), 500
    
    except Exception as e:
        app.logger.error(f"Unexpected Error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

def getConfigId(configs_response):
    config_id = None
    for config in configs_response.findall('config'):
        config_name = config.find('name').text
        if config_name == configName:
            config_id = config.get('id')
            app.logger.info(f"ID: {config_id}")
            break
    return config_id

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
