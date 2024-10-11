import time

def create_task(gmp, scannerID, targetID, config_id, host):
    task_response = gmp.create_task(name="task test: "+ str(host), scanner_id=scannerID, target_id=targetID, config_id=config_id)
    if task_response.get('status') in ["200", "201"]:
        return task_response.get('id')
    else:
        raise Exception(f"Error creation task: {task_response.get('status_text')}")

def startTask(gmp, taskID):
    start = gmp.start_task(task_id=taskID)
    if start.get('status') in ["200", "201", "202"]:
        while True:
            time.sleep(10)
            task_status = gmp.get_task(task_id=taskID).find('task/status').text
            if task_status == 'Done':
                break
    else:
        raise Exception(f"Error start task: {start.get('status_text')}")
