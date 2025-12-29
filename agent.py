def run(tasks):
    results = []
    for task in tasks.get("tasks", []):
        if task["type"] == "add":
            results.append(task["a"] + task["b"])
        elif task["type"] == "multiply":
            results.append(task["a"] * task["b"])
        else:
            results.append(None)
    return {"results": results}
