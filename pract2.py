def osv_fetch_vul(comp_data):
    print("Fetching vulnerabilities from OSV.dev...")
    osv_query_batch_url = "https://api.osv.dev/v1/querybatch"
    osv_vuln_detail_url = "https://api.osv.dev/v1/vulns/"

    quries = []
    for i, component in enumerate(comp_data):
        purl = component.get('purl')
        if purl:
            quries.append({"package": {"purl": purl}})
    if not quries:
        print("No PURL found!!!")
        return comp_data, {
            "labels": ['Critical', 'High', 'Medium', 'Low', 'None'],
            "data": [0, 0, 0, 0, 0]
        }
    payload = {"queries": quries}
    vul_count = Counter({
        'Critical': 0, 'High': 0,'Moderate':0, 'Low': 0, 'None': 0
    })

    try:
        response = requests.post(osv_query_batch_url, json=payload, timeout=60)
        osv_result = response.json()
        c = 0
        index = [i for i, r in enumerate(osv_result['results']) if 'vulns' in r]
        for i in index:
           comp_data[i]["vulnerabilities"] = len(osv_result['results'][i]['vulns'])
           c+= 1
        vul_ids = [vuln['id'] for i in index for vuln in osv_result['results'][i]['vulns']]
        for id in vul_ids:
            response = requests.get(f"{osv_vuln_detail_url}{id}", timeout=10)
            vuln_detail = response.json()
            osv_severity_array = vuln_detail.get('database_specific', [])
            if osv_severity_array:
                severity = osv_severity_array['severity']
                vul_count[severity] += 1 
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from OSV: {e}")
        return comp_data, {
            "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'],
            "data": [0, 0, 0, 0, 0]
        }
    except Exception as e:
        print(f"Error fetching data from OSV: {e}")
        return comp_data, {
            "labels": ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'],
            "data": [0, 0, 0, 0, 0]
        }
    vulnerability_chart_data = {
        "labels": ['Critical', 'High', 'Medium', 'Low', 'None'],
        "data": [
            vul_count['CRITICAL'],
            vul_count['HIGH'],
            vul_count['MODERATE'],
            vul_count['LOW'],
            vul_count['NONE']
        ]
    }
    return comp_data, vulnerability_chart_data