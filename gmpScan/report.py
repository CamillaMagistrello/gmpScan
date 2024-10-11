from lxml import etree
from gvm.errors import GvmError

def get_report_id(gmp, taskID, targetID):
    try:
        report_response = gmp.get_reports()
        for report in report_response.findall('.//report'):
            task_report = report.find('.//task')
            task_id_report_elem = task_report.get('id')
            target_report = report.find('.//target')
            target_id_report_elem = target_report.get('id')
            if task_id_report_elem is not None and target_id_report_elem is not None:
                if task_id_report_elem == taskID and target_id_report_elem == targetID:
                    return report.get('id')
        raise Exception("Report ID not found.")
    except GvmError as e:
        raise Exception(f"Error retrieving report ID: {str(e)}")

def saveInFile(xmlToSave, name):
    content = etree.tostring(xmlToSave, pretty_print=True, encoding='utf-8', xml_declaration=True)
    with open(name + ".txt", 'wb') as file: 
        file.write(content)
