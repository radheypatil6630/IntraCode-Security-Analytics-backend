import requests
import json
import subprocess
import sys
from backend import sbom_processor
from collections import Counter
SYFT_PATH = "syft"  # Ensure this is the correct path to the Syft executable
def _run_syft_command(command_args, input_data=None):
    """Helper to run Syft subprocess and return JSON output."""
    # Correctly build the command list for subprocess.run
    full_command = [SYFT_PATH] + command_args
    print(f"Running Syft command: {' '.join(full_command)}") # For debugging
    try:
        process = subprocess.run(
            full_command,
            capture_output=True,
            text=True, # Capture stdout/stderr as text
            check=True, # Raise CalledProcessError for non-zero exit codes
            input=input_data # Pass input_data to stdin if provided (e.g., for piping SBOM)
        )
        # Check if stdout is empty before trying to load JSON
        if not process.stdout.strip():
            raise ValueError("Syft command produced empty output. No SBOM data generated.")
        
        return json.loads(process.stdout)
    except subprocess.CalledProcessError as e:
        # Syft returned a non-zero exit code (an error occurred within Syft)
        print(f"Syft command failed with error (return code {e.returncode}): {e.stderr}")
        raise RuntimeError(f"Syft command failed: {e.stderr}")
    except json.JSONDecodeError as e:
        # Syft output was not valid JSON
        print(f"Failed to parse Syft output as JSON: {e}")
        print(f"Syft stdout (partial): {process.stdout[:500]}...") # Print partial output for debug
        print(f"Syft stderr: {process.stderr}")
        raise RuntimeError(f"Syft output not valid JSON: {e}")
    except FileNotFoundError:
        # Syft executable itself was not found
        raise FileNotFoundError(f"Syft command not found. Ensure '{SYFT_PATH}' is correct and executable.")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"An unexpected error occurred while running Syft: {e}")
        raise
    
def osv_fetch_vul(comp_data):
    print("Fetching vulnerabilities from OSV.dev...")
    osv_query_batch_url = "https://api.osv.dev/v1/querybatch"
    osv_vuln_detail_url = "https://api.osv.dev/v1/vulns/"

    quries = []
    comp_map = {}
    for i, component in enumerate(comp_data):
        purl = component.get('purl')
        comp_map[purl] = i
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
        print(osv_result)
        index = [i for i, r in enumerate(osv_result['results']) if 'vulns' in r]
        s_dict = {key: [] for key in index}
        print(s_dict)
        for i in index:
           comp_data[i]["vulnerabilities"] = len(osv_result['results'][i]['vulns'])
           c+= 1
        vul_ids = [vuln['id'] for i in index for vuln in osv_result['results'][i]['vulns']]
        for id in vul_ids:
            response = requests.get(f"{osv_vuln_detail_url}{id}", timeout=10)
            vuln_detail = response.json()
            print(vuln_detail)
            osv_severity = vuln_detail.get('database_specific',[]).get('severity', [])
            osv_name = vuln_detail['affected'][0]['package']['name']
            for name in comp_data:
                i = comp_map.get(name['purl'])    
                if name['name'] == osv_name:
                    s_dict[i].append(osv_severity)
                    # print(s_dict)
            osv_severity_array = vuln_detail.get('database_specific', [])
            if osv_severity_array:
                severity = osv_severity_array['severity']
                vul_count[severity] += 1 
        for i,compo in enumerate(comp_data):
            for j in index:
                if j in s_dict and s_dict[j]:
                    comp_data[j]["severities"] = s_dict[j] 
            else:
                comp_data[i]["severities"] = ['NONE']
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

def process_existing_sbom(json_filepath):
    try:
        if json_filepath.endswith('.xml'):
            print(f"Processing XML SBOM file: {json_filepath} converting to JSON")
            data = _run_syft_command(["convert", json_filepath, "--output", "cyclonedx-json"])
        else:
            with open(json_filepath, 'r', encoding='utf-8') as file:
                data = file.read()
        getdata = json.loads(data) 
        get_format = getdata.get('bomFormat', '')
        if get_format != 'CycloneDX':
            raise ValueError("Uploaded file is not a valid CycloneDX SBOM format.")
        else:
            print(data)
            # print(dict(data))
            # return sbom_processor.process_cyclonedx_sbom_data(data)
        print(f"SBOM format detected: {get_format}")
    except ValueError as e:
        raise ValueError(f"Uploaded file is not a valid SBOM: {e}")
    
file = sys.argv[1]
# with open(file, 'r') as f:
# 	data = json.load(f)
# comp_data = data.get("components",[])
# osv_fetch_vul(comp_data)
# osv_fetch_vul(data)

print(process_existing_sbom(file))
