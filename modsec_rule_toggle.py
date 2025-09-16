import os
import json
import re
import argparse
import sys
from datetime import datetime
import subprocess

def load_config():
    with open('config.json', 'r') as f:
        return json.load(f)

config = load_config()

RULE_DIR = config['RULE_DIR']
RULE_STATE_FILE = config['RULE_STATE_FILE']
MONITOR_RULES_FILE = config['MONITOR_RULES_FILE']
DISABLED_RULES_FILE = config['DISABLED_RULES_FILE']

# Scoring values for different paranoia levels and rule types
# Based on OWASP CRS v4 scoring system
RULE_SCORES = {
    # Critical severity rules
    'critical': {
        'pl1': 5,  # Paranoia Level 1
        'pl2': 4,  # Paranoia Level 2
        'pl3': 3,  # Paranoia Level 3
        'pl4': 2   # Paranoia Level 4
    },
    # Error severity rules
    'error': {
        'pl1': 4,
        'pl2': 3,
        'pl3': 2,
        'pl4': 1
    },
    # Warning severity rules
    'warning': {
        'pl1': 3,
        'pl2': 2,
        'pl3': 1,
        'pl4': 1
    },
    # Notice severity rules
    'notice': {
        'pl1': 2,
        'pl2': 1,
        'pl3': 1,
        'pl4': 1
    }
}

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")

def init_rule_state_file():
    if not os.path.exists(RULE_STATE_FILE):
        os.makedirs(os.path.dirname(RULE_STATE_FILE), exist_ok=True)
        with open(RULE_STATE_FILE, "w") as f:
            json.dump({"disabled_rules": {}, "monitor_rules": {}}, f)
        log(f"Initialized rule state file at {RULE_STATE_FILE}")

def load_state():
    log(f"Loading rule state from {RULE_STATE_FILE}")
    init_rule_state_file()
    with open(RULE_STATE_FILE) as f:
        state = json.load(f)
        # Ensure both keys exist for backward compatibility
        if "monitor_rules" not in state:
            state["monitor_rules"] = {}
        if "disabled_rules" not in state:
            state["disabled_rules"] = {}
        return state

def save_state(state):
    with open(RULE_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    log(f"Saved updated rule state to {RULE_STATE_FILE}")

def get_monitor_rules_header():
    """Obtiene el header para el archivo de reglas monitor"""
    return """# ================================================================
# CUSTOM MONITOR RULES - ModSecurity Management Panel
# ================================================================
#
# This file contains SecRuleUpdateActionById directives to set
# rules to monitor mode (logging without blocking) for CRS v4.
#
# For OWASP CRS v4 in Anomaly Scoring mode, monitor mode requires
# neutralizing the anomaly score contribution of the rule.
#
# DO NOT MODIFY THIS FILE DIRECTLY - Use the management panel
# ================================================================

"""

def get_disabled_rules_header():
    """Obtiene el header para el archivo de reglas deshabilitadas"""
    return """# ================================================================
# DISABLED RULES - ModSecurity Management Panel
# ================================================================
#
# This file contains SecRuleRemoveById directives to disable rules.
#
# DO NOT MODIFY THIS FILE DIRECTLY - Use the management panel
# ================================================================

"""

def get_rule_score_and_paranoia(rule_id):
    """
    Determina el score y nivel de paranoia de una regla basándose en su ID.
    Returns: (score, paranoia_level, severity)
    """
    rule_id_int = int(rule_id)

    # Determine paranoia level based on rule ID ranges (CRS v4 convention)
    if rule_id_int < 920000:
        paranoia = 'pl1'
    elif rule_id_int < 940000:
        paranoia = 'pl1'  # Most core rules are PL1
    elif rule_id_int < 950000:
        paranoia = 'pl2' if rule_id_int >= 942000 else 'pl1'
    elif rule_id_int < 960000:
        paranoia = 'pl3'
    else:
        paranoia = 'pl4'

    # Determine severity based on rule ID and type
    # This is a simplified approach - in reality you'd parse the actual rule
    if rule_id_int in range(920000, 921000):  # Protocol violations
        severity = 'error'
    elif rule_id_int in range(930000, 935000):  # Application attacks
        severity = 'critical'
    elif rule_id_int in range(941000, 943000):  # XSS/SQLi attacks
        severity = 'critical'
    elif rule_id_int in range(950000, 960000):  # Data leakages
        severity = 'warning'
    else:
        severity = 'error'  # Default

    score = RULE_SCORES.get(severity, {}).get(paranoia, 4)  # Default score

    return score, paranoia, severity

def find_rule_in_files(rule_id):
    """Find which file contains the specified rule"""
    for filename in os.listdir(RULE_DIR):
        if not filename.endswith(".conf"):
            continue

        # Skip our custom files
        if filename in ["RESPONSE-999-CUSTOM-RULES.conf", "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"]:
            continue

        path = os.path.join(RULE_DIR, filename)
        try:
            with open(path, "r") as f:
                content = f.read()
                if re.search(rf"id[:=]['\"]?{rule_id}['\"]?\b", content.replace(" ", "")):
                    return filename, path
        except Exception as e:
            log(f"Error reading {path}: {e}")
            continue
    return None, None

def regenerate_monitor_rules_file():
    """Regenera el archivo de reglas en modo monitor para CRS v4 Anomaly Scoring"""
    state = load_state()
    monitor_rules = state.get("monitor_rules", {})

    # Asegurar que el archivo existe
    os.makedirs(os.path.dirname(MONITOR_RULES_FILE), exist_ok=True)

    content = get_monitor_rules_header()

    if monitor_rules:
        content += "# Monitor Mode Rules for CRS v4 Anomaly Scoring\n"
        content += "# These rules will log but not contribute to anomaly score\n\n"

        for rule_id, rule_info in monitor_rules.items():
            score, paranoia, severity = get_rule_score_and_paranoia(rule_id)

            content += f"# Rule {rule_id} - Set to monitor mode\n"
            content += f"# File: {rule_info.get('file', 'unknown')}\n"
            content += f"# Monitored at: {rule_info.get('monitored_at', 'unknown')}\n"
            content += f"# Severity: {severity}, Paranoia: {paranoia}, Score: {score}\n"

            # Method 1: Neutralize the anomaly score contribution
            # This keeps the rule active for logging but prevents blocking
            content += f'SecRuleUpdateActionById {rule_id} "pass,log,setvar:\'tx.inbound_anomaly_score_pl1=-{score}\'"\n'

            # Alternative method (commented out): Complete score neutralization
            # content += f'SecRuleUpdateActionById {rule_id} "pass,log,setvar:\'tx.anomaly_score_pl1=-{score}\',setvar:\'tx.inbound_anomaly_score=-{score}\'"\n'

            content += "\n"
    else:
        content += "# No rules currently in monitor mode\n\n"

    with open(MONITOR_RULES_FILE, 'w') as f:
        f.write(content)

    log(f"Regenerated monitor rules file with {len(monitor_rules)} rules for CRS v4")

def regenerate_disabled_rules_file():
    """Regenera el archivo de reglas deshabilitadas"""
    state = load_state()
    disabled_rules = state.get("disabled_rules", {})

    # Leer contenido existente para preservar otras exclusiones
    existing_content = ""
    custom_section_start = "# ================================================================\n# DISABLED RULES - ModSecurity Management Panel"

    if os.path.exists(DISABLED_RULES_FILE):
        with open(DISABLED_RULES_FILE, 'r') as f:
            content = f.read()
            # Encontrar donde empieza nuestra sección y mantener todo lo anterior
            if custom_section_start in content:
                existing_content = content[:content.find(custom_section_start)]
            else:
                existing_content = content

    # Construir nuevo contenido
    content = existing_content.rstrip() + "\n\n" if existing_content.strip() else ""
    content += get_disabled_rules_header()

    if disabled_rules:
        content += "# Disabled Rules\n"
        content += "# These rules are completely removed from processing\n\n"

        for rule_id, rule_info in disabled_rules.items():
            content += f"# Rule {rule_id} - Disabled\n"
            content += f"# File: {rule_info.get('file', 'unknown')}\n"
            content += f"# Disabled at: {rule_info.get('disabled_at', 'unknown')}\n"
            content += f'SecRuleRemoveById {rule_id}\n\n'
    else:
        content += "# No rules currently disabled\n\n"

    with open(DISABLED_RULES_FILE, 'w') as f:
        f.write(content)

    log(f"Regenerated disabled rules file with {len(disabled_rules)} rules")

def disable_rule(rule_id):
    """Deshabilita una regla usando SecRuleRemoveById"""
    rule_id = str(rule_id)
    log(f"Disabling rule {rule_id}")
    state = load_state()

    # Remove from monitor rules if it was there
    if rule_id in state.get('monitor_rules', {}):
        del state['monitor_rules'][rule_id]
        log(f"Removed rule {rule_id} from monitor mode")

    # Find rule file for record keeping
    filename, _ = find_rule_in_files(rule_id)
    if not filename:
        log(f"Warning: Rule {rule_id} not found in rule files, but will be disabled anyway")
        filename = "unknown"

    # Add to disabled rules
    state['disabled_rules'][rule_id] = {
        "file": filename,
        "disabled_at": datetime.now().isoformat()
    }

    save_state(state)
    regenerate_disabled_rules_file()
    regenerate_monitor_rules_file()

    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], check=True)
        log("Nginx reloaded successfully")
    except subprocess.CalledProcessError as e:
        log(f"Error reloading nginx: {e}")
        raise

    log(f"Rule {rule_id} disabled successfully")

def monitor_rule(rule_id):
    """Pone una regla en modo monitor usando score neutralization para CRS v4"""
    rule_id = str(rule_id)
    log(f"Setting rule {rule_id} to monitor mode (CRS v4 Anomaly Scoring)")
    state = load_state()

    # Remove from disabled rules if it was there
    if rule_id in state.get('disabled_rules', {}):
        del state['disabled_rules'][rule_id]
        log(f"Removed rule {rule_id} from disabled rules")

    # Find rule file for record keeping
    filename, _ = find_rule_in_files(rule_id)
    if not filename:
        log(f"Warning: Rule {rule_id} not found in rule files, but will be set to monitor mode anyway")
        filename = "unknown"

    # Get rule scoring information
    score, paranoia, severity = get_rule_score_and_paranoia(rule_id)

    # Add to monitor rules
    state['monitor_rules'][rule_id] = {
        "file": filename,
        "monitored_at": datetime.now().isoformat(),
        "score": score,
        "paranoia": paranoia,
        "severity": severity
    }

    save_state(state)
    regenerate_monitor_rules_file()
    regenerate_disabled_rules_file()

    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], check=True)
        log("Nginx reloaded successfully")
    except subprocess.CalledProcessError as e:
        log(f"Error reloading nginx: {e}")
        raise

    log(f"Rule {rule_id} set to monitor mode successfully (score neutralized: -{score})")

def enable_rule(rule_id):
    """Habilita una regla removiéndola de disabled y monitor"""
    rule_id = str(rule_id)
    log(f"Enabling rule {rule_id}")
    state = load_state()

    was_disabled = rule_id in state.get('disabled_rules', {})
    was_monitor = rule_id in state.get('monitor_rules', {})

    # Remove from both disabled and monitor rules
    if was_disabled:
        del state['disabled_rules'][rule_id]
        log(f"Removed rule {rule_id} from disabled rules")

    if was_monitor:
        del state['monitor_rules'][rule_id]
        log(f"Removed rule {rule_id} from monitor rules")

    if not was_disabled and not was_monitor:
        log(f"Rule {rule_id} is already in normal blocking mode")
        return True

    save_state(state)
    regenerate_disabled_rules_file()
    regenerate_monitor_rules_file()

    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'nginx'], check=True)
        log("Nginx reloaded successfully")
    except subprocess.CalledProcessError as e:
        log(f"Error reloading nginx: {e}")
        raise

    log(f"Rule {rule_id} enabled successfully (normal blocking mode)")
    return True

def get_rule_status(rule_id):
    """Get the current status of a rule"""
    state = load_state()

    if rule_id in state.get('disabled_rules', {}):
        return "disabled"
    elif rule_id in state.get('monitor_rules', {}):
        return "monitor"
    else:
        return "block"

def cleanup_orphaned_rules():
    """Limpia reglas huérfanas que no existen en los archivos"""
    state = load_state()
    cleaned_disabled = {}
    cleaned_monitor = {}

    # Check disabled rules
    for rule_id, rule_info in state.get('disabled_rules', {}).items():
        filename, _ = find_rule_in_files(rule_id)
        if filename:  # Rule still exists
            cleaned_disabled[rule_id] = rule_info
        else:
            log(f"Removing orphaned disabled rule: {rule_id}")

    # Check monitor rules
    for rule_id, rule_info in state.get('monitor_rules', {}).items():
        filename, _ = find_rule_in_files(rule_id)
        if filename:  # Rule still exists
            cleaned_monitor[rule_id] = rule_info
        else:
            log(f"Removing orphaned monitor rule: {rule_id}")

    # Update state if anything changed
    if (len(cleaned_disabled) != len(state.get('disabled_rules', {})) or
        len(cleaned_monitor) != len(state.get('monitor_rules', {}))):

        state['disabled_rules'] = cleaned_disabled
        state['monitor_rules'] = cleaned_monitor
        save_state(state)
        regenerate_disabled_rules_file()
        regenerate_monitor_rules_file()

        log("Cleanup completed - orphaned rules removed")
        return True

    log("No orphaned rules found")
    return False

def test_crs_configuration():
    """Test if CRS is in Anomaly Scoring mode"""
    try:
        # Look for anomaly scoring indicators in CRS setup
        crs_setup_path = config['CRS_SETUP_PATH']
        if os.path.exists(crs_setup_path):
            with open(crs_setup_path, 'r') as f:
                content = f.read()
                if 'tx.anomaly_score_threshold' in content:
                    log("CRS v4 Anomaly Scoring mode detected")
                    return True

        log("Warning: Could not determine CRS mode, assuming Anomaly Scoring")
        return True
    except Exception as e:
        log(f"Error checking CRS configuration: {e}")
        return True

def main():
    log("=== ModSecurity Rule Toggle Script Started (CRS v4 Compatible) ===")
    parser = argparse.ArgumentParser(description="Enable, disable, or monitor ModSecurity rules for CRS v4.")
    parser.add_argument("--rule-id", required=True, help="The ModSecurity rule ID to modify")
    parser.add_argument("--action", required=True, choices=["block", "monitor", "disabled"],
                       help="Action to perform on the rule")
    parser.add_argument("--cleanup", action="store_true",
                       help="Remove orphaned rules from state before processing")

    args = parser.parse_args()
    log(f"Arguments received: rule_id={args.rule_id}, action={args.action}")

    try:
        # Test CRS configuration
        test_crs_configuration()

        if args.cleanup:
            cleanup_orphaned_rules()

        if args.action == "disabled":
            disable_rule(args.rule_id)
        elif args.action == "block":
            enable_rule(args.rule_id)
        elif args.action == "monitor":
            monitor_rule(args.rule_id)
        else:
            log(f"Unknown action: {args.action}")
            sys.exit(1)

    except Exception as e:
        log(f"Error: {e}")
        sys.exit(1)

    log("=== Script Finished Successfully ===")

if __name__ == "__main__":
    main()
