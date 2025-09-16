import os
import re
import glob
import csv
import base64
import shutil
import tempfile
import json
import subprocess
from collections import defaultdict
from datetime import datetime
from io import StringIO
from typing import Optional, List, Dict, Union
from enum import Enum
from pathlib import Path

from fastapi import FastAPI, Request, Query, HTTPException, status
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import matplotlib.pyplot as plt
from weasyprint import HTML
from pydantic import BaseModel, Field

from parser import parse_modsec_log
from parser import extract_rule_descriptions_from_log
from models import LogEntry, RuleMessage, ModSecRule, RuleAction
from modsec_rule_toggle import disable_rule, enable_rule, monitor_rule, log, load_state, save_state, cleanup_orphaned_rules

# Cargar configuración (solo estas líneas)
def load_config():
    with open('config.json', 'r') as f:
        return json.load(f)

config = load_config()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

PER_PAGE = 20
LOG_FILE_PATH = config['LOG_FILE_PATH']
LOG_ENTRIES: List[LogEntry] = []
RULE_FILES_GLOB = config['RULE_FILES_GLOB']
RULE_STATE_FILE = config['RULE_STATE_FILE']
RULE_DIR = config['RULE_DIR']
CUSTOM_RULES_FILE = config['CUSTOM_RULES_FILE']
# In-memory rule change queue
PENDING_RULE_UPDATES: Dict[str, RuleAction] = {}

# Configuración de archivos de exclusiones
EXCLUSIONS_DIR = config['EXCLUSIONS_DIR']
EXCLUSIONS_FILE = config['EXCLUSIONS_FILE']
EXCLUSIONS_STATE_FILE = config['EXCLUSIONS_STATE_FILE']

# Modelos para exclusiones
class ExclusionType(str, Enum):
    REMOVE_BY_ID = "ruleRemoveById"
    REMOVE_BY_TAG = "ruleRemoveByTag"
    REMOVE_TARGET_BY_ID = "ruleRemoveTargetById"
    REMOVE_TARGET_BY_TAG = "ruleRemoveTargetByTag"
    DISABLE_ENGINE = "ruleEngine=Off"

class ExclusionCondition(str, Enum):
    REQUEST_URI = "REQUEST_URI"
    REQUEST_FILENAME = "REQUEST_FILENAME"
    REMOTE_ADDR = "REMOTE_ADDR"
    REQUEST_HEADERS_HOST = "REQUEST_HEADERS:Host"
    REQUEST_HEADERS_USER_AGENT = "REQUEST_HEADERS:User-Agent"
    ARGS = "ARGS"
    REQUEST_METHOD = "REQUEST_METHOD"

class ExclusionOperator(str, Enum):
    BEGINS_WITH = "@beginsWith"
    ENDS_WITH = "@endsWith"
    CONTAINS = "@contains"
    EQUALS = "@eq"
    IP_MATCH = "@ipMatch"
    REGEX = "@rx"

class ExclusionRule(BaseModel):
    id: Optional[str] = None
    name: str = Field(..., description="Nombre descriptivo de la exclusión")
    description: Optional[str] = Field(None, description="Descripción detallada")
    condition_variable: str = Field(..., description="Variable a evaluar")
    operator: str = Field(..., description="Operador de comparación")
    condition_value: str = Field(..., description="Valor a comparar")
    exclusion_type: str = Field(..., description="Tipo de exclusión")
    exclusion_value: str = Field(..., description="Valor de la exclusión (rule_id, tag, etc.)")
    target: Optional[str] = Field(None, description="Target específico para exclusiones de target")
    phase: int = Field(1, description="Fase de ModSecurity (1-5)")
    enabled: bool = Field(True, description="Si la exclusión está activa")
    created_at: datetime = Field(default_factory=datetime.now)
    last_modified: datetime = Field(default_factory=datetime.now)

class ExclusionCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    condition_variable: str
    operator: str
    condition_value: str
    exclusion_type: str
    exclusion_value: str
    target: Optional[str] = None
    phase: int = 1

class ExclusionUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None

class ExclusionManager:
    """Gestor de exclusiones de ModSecurity"""

    def __init__(self):
        self.ensure_exclusions_file()
        self.ensure_state_file()
        self.clean_corrupted_file()

    def clean_corrupted_file(self):
        """Limpia archivos corruptos existentes"""
        try:
            if os.path.exists(EXCLUSIONS_FILE):
                with open(EXCLUSIONS_FILE, 'r') as f:
                    content = f.read()

                # Si contiene referencias a las clases, limpiar
                if 'ExclusionCondition.' in content or 'ExclusionOperator.' in content:
                    print("Detected corrupted exclusions file, cleaning...")
                    with open(EXCLUSIONS_FILE, 'w') as f:
                        f.write(self._get_file_header())
                    print("Exclusions file cleaned")
        except Exception as e:
            print(f"Error cleaning file: {e}")

    def ensure_exclusions_file(self):
        """Asegura que el archivo de exclusiones existe"""
        if not os.path.exists(EXCLUSIONS_FILE):
            os.makedirs(os.path.dirname(EXCLUSIONS_FILE), exist_ok=True)
            with open(EXCLUSIONS_FILE, 'w') as f:
                f.write(self._get_file_header())

    def ensure_state_file(self):
        """Asegura que el archivo de estado existe"""
        if not os.path.exists(EXCLUSIONS_STATE_FILE):
            os.makedirs(os.path.dirname(EXCLUSIONS_STATE_FILE), exist_ok=True)
            with open(EXCLUSIONS_STATE_FILE, 'w') as f:
                json.dump({"exclusions": {}}, f, indent=2)

    def _get_file_header(self) -> str:
        """Obtiene el header del archivo de exclusiones"""
        return """# ----------------------------------------------------------------
# Custom ModSecurity Exclusion Rules
# Generated by ModSecurity Management Panel
# ----------------------------------------------------------------
#
# This file contains custom exclusion rules to handle false positives
# and application-specific requirements.
#
# DO NOT MODIFY THIS FILE DIRECTLY - Use the management panel instead
# ----------------------------------------------------------------

"""

    def _generate_rule_id(self) -> str:
        """Genera un ID único para la exclusión"""
        timestamp = int(datetime.now().timestamp())
        return f"90000{timestamp % 10000}"

    def _generate_exclusion_rule_text(self, exclusion: ExclusionRule) -> str:
        """Genera el texto de la regla de exclusión"""
        rule_id = exclusion.id or self._generate_rule_id()

        # Asegurar que usamos strings directamente
        condition_var = str(exclusion.condition_variable)
        operator = str(exclusion.operator)
        condition_value = str(exclusion.condition_value)
        exclusion_type = str(exclusion.exclusion_type)
        exclusion_value = str(exclusion.exclusion_value)

        # Debug print
        print(f"DEBUG: Generating rule for {exclusion.name}")
        print(f"  condition_var: {condition_var}")
        print(f"  operator: {operator}")
        print(f"  exclusion_type: {exclusion_type}")

        # Construir la condición
        condition = f'{condition_var} "{operator} {condition_value}"'

        # Construir la acción de exclusión
        if exclusion_type == "ruleEngine=Off":
            exclusion_action = "ctl:ruleEngine=Off"
        elif exclusion_type == "ruleRemoveTargetById":
            if exclusion.target:
                exclusion_action = f"ctl:ruleRemoveTargetById={exclusion_value};{exclusion.target}"
            else:
                exclusion_action = f"ctl:ruleRemoveTargetById={exclusion_value}"
        elif exclusion_type == "ruleRemoveTargetByTag":
            if exclusion.target:
                exclusion_action = f"ctl:ruleRemoveTargetByTag={exclusion_value};{exclusion.target}"
            else:
                exclusion_action = f"ctl:ruleRemoveTargetByTag={exclusion_value}"
        else:
            exclusion_action = f"ctl:{exclusion_type}={exclusion_value}"

        # Generar comentario descriptivo
        comment = f"# {exclusion.name}"
        if exclusion.description:
            comment += f"\n# {exclusion.description}"

        # Generar la regla completa
        rule_text = f"""{comment}
SecRule {condition} \\
    "id:{rule_id},\\
    phase:{exclusion.phase},\\
    pass,\\
    nolog,\\
    {exclusion_action}"

"""

        # Debug print del resultado
        print(f"Generated rule text:\n{rule_text}")

        return rule_text

    def load_exclusions_state(self) -> Dict:
        """Carga el estado de las exclusiones"""
        try:
            with open(EXCLUSIONS_STATE_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"exclusions": {}}

    def save_exclusions_state(self, state: Dict):
        """Guarda el estado de las exclusiones"""
        with open(EXCLUSIONS_STATE_FILE, 'w') as f:
            json.dump(state, f, indent=2, default=str)

    def get_all_exclusions(self) -> List[ExclusionRule]:
        """Obtiene todas las exclusiones"""
        state = self.load_exclusions_state()
        exclusions = []

        for exclusion_id, data in state.get("exclusions", {}).items():
            try:
                # Asegurar que created_at y last_modified son datetime objects
                if isinstance(data.get('created_at'), str):
                    data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
                if isinstance(data.get('last_modified'), str):
                    data['last_modified'] = datetime.fromisoformat(data['last_modified'].replace('Z', '+00:00'))

                exclusion = ExclusionRule(
                    id=exclusion_id,
                    **data
                )
                exclusions.append(exclusion)
            except Exception as e:
                print(f"Error loading exclusion {exclusion_id}: {e}")
                continue

        return exclusions

    def get_exclusion(self, exclusion_id: str) -> Optional[ExclusionRule]:
        """Obtiene una exclusión específica"""
        state = self.load_exclusions_state()
        exclusion_data = state.get("exclusions", {}).get(exclusion_id)

        if exclusion_data:
            try:
                if isinstance(exclusion_data.get('created_at'), str):
                    exclusion_data['created_at'] = datetime.fromisoformat(exclusion_data['created_at'].replace('Z', '+00:00'))
                if isinstance(exclusion_data.get('last_modified'), str):
                    exclusion_data['last_modified'] = datetime.fromisoformat(exclusion_data['last_modified'].replace('Z', '+00:00'))

                return ExclusionRule(id=exclusion_id, **exclusion_data)
            except Exception as e:
                print(f"Error loading exclusion {exclusion_id}: {e}")
        return None

    def create_exclusion(self, exclusion_request: ExclusionCreateRequest) -> ExclusionRule:
        """Crea una nueva exclusión"""
        exclusion_data = exclusion_request.dict()
        exclusion_data['created_at'] = datetime.now()
        exclusion_data['last_modified'] = datetime.now()

        exclusion = ExclusionRule(
            id=self._generate_rule_id(),
            **exclusion_data
        )

        print(f"Creating exclusion: {exclusion.name}")
        print(f"Request data: {exclusion_request.dict()}")

        # Guardar en el estado - convertir a dict para JSON
        state = self.load_exclusions_state()
        exclusion_dict = exclusion.dict(exclude={"id"})
        state["exclusions"][exclusion.id] = exclusion_dict
        self.save_exclusions_state(state)

        # Regenerar archivo de exclusiones
        self._regenerate_exclusions_file()

        return exclusion

    def update_exclusion(self, exclusion_id: str, update_request: ExclusionUpdateRequest) -> Optional[ExclusionRule]:
        """Actualiza una exclusión existente"""
        state = self.load_exclusions_state()
        exclusion_data = state.get("exclusions", {}).get(exclusion_id)

        if not exclusion_data:
            return None

        # Actualizar campos
        update_data = update_request.dict(exclude_unset=True)
        if update_data:
            exclusion_data.update(update_data)
            exclusion_data["last_modified"] = datetime.now()
            state["exclusions"][exclusion_id] = exclusion_data
            self.save_exclusions_state(state)

            # Regenerar archivo si se habilitó/deshabilitó
            if "enabled" in update_data:
                self._regenerate_exclusions_file()

        # Crear object para retorno
        if isinstance(exclusion_data.get('created_at'), str):
            exclusion_data['created_at'] = datetime.fromisoformat(exclusion_data['created_at'].replace('Z', '+00:00'))
        if isinstance(exclusion_data.get('last_modified'), str):
            exclusion_data['last_modified'] = datetime.fromisoformat(exclusion_data['last_modified'].replace('Z', '+00:00'))

        return ExclusionRule(id=exclusion_id, **exclusion_data)

    def delete_exclusion(self, exclusion_id: str) -> bool:
        """Elimina una exclusión"""
        state = self.load_exclusions_state()

        if exclusion_id in state.get("exclusions", {}):
            del state["exclusions"][exclusion_id]
            self.save_exclusions_state(state)
            self._regenerate_exclusions_file()
            return True

        return False

    def _regenerate_exclusions_file(self):
        """Regenera el archivo de exclusiones completo"""
        exclusions = self.get_all_exclusions()
        enabled_exclusions = [ex for ex in exclusions if ex.enabled]

        content = self._get_file_header()

        for exclusion in enabled_exclusions:
            content += self._generate_exclusion_rule_text(exclusion) + "\n"

        print(f"Writing {len(enabled_exclusions)} exclusions to {EXCLUSIONS_FILE}")

        # Escribir archivo
        with open(EXCLUSIONS_FILE, 'w') as f:
            f.write(content)

        print(f"Exclusions file updated successfully")

        # Recargar nginx
        try:
            result = subprocess.run(['systemctl', 'reload', 'nginx'],
                                  check=True, capture_output=True, text=True)
            print("Nginx reloaded successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error reloading nginx: {e}")
            print(f"Stdout: {e.stdout}")
            print(f"Stderr: {e.stderr}")
            raise

class CustomRulesManager:
    """Gestor mejorado de reglas personalizadas de ModSecurity con soporte para estados"""

    def __init__(self):
        self.ensure_custom_rules_file()
        self.custom_rules_state_file = "/etc/modsecurity.d/owasp-crs/rules/custom_rules_state.json"
        self.ensure_state_file()

    def ensure_custom_rules_file(self):
        """Asegura que el archivo de reglas personalizadas existe"""
        if not os.path.exists(CUSTOM_RULES_FILE):
            os.makedirs(os.path.dirname(CUSTOM_RULES_FILE), exist_ok=True)
            with open(CUSTOM_RULES_FILE, 'w') as f:
                f.write(self._get_custom_rules_header())

    def ensure_state_file(self):
        """Asegura que el archivo de estado de custom rules existe"""
        if not os.path.exists(self.custom_rules_state_file):
            os.makedirs(os.path.dirname(self.custom_rules_state_file), exist_ok=True)
            with open(self.custom_rules_state_file, 'w') as f:
                json.dump({"custom_rules": {}}, f, indent=2)

    def _get_custom_rules_header(self) -> str:
        """Obtiene el header del archivo de reglas personalizadas"""
        return """# ================================================================
# CUSTOM MODSECURITY RULES
# ================================================================
# This file contains custom rules created through the management panel
# DO NOT MODIFY THIS FILE DIRECTLY - Use the management panel instead
# ================================================================

"""

    def _extract_rule_id(self, rule_text: str) -> str:
        """Extrae el ID de una regla desde su texto"""
        match = re.search(r'id[:=]["\']?(\d+)["\']?', rule_text)
        return match.group(1) if match else None

    def load_custom_rules_state(self) -> Dict:
        """Carga el estado de las custom rules"""
        try:
            with open(self.custom_rules_state_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"custom_rules": {}}

    def save_custom_rules_state(self, state: Dict):
        """Guarda el estado de las custom rules"""
        with open(self.custom_rules_state_file, 'w') as f:
            json.dump(state, f, indent=2, default=str)

    def get_all_custom_rules(self) -> List[dict]:
        """Obtiene todas las reglas personalizadas con su estado"""
        try:
            if not os.path.exists(CUSTOM_RULES_FILE):
                return []

            with open(CUSTOM_RULES_FILE, 'r') as f:
                content = f.read()

            rules = []
            state = self.load_custom_rules_state()
            custom_rules_state = state.get("custom_rules", {})

            # Buscar reglas SecRule
            rule_pattern = re.compile(
                r'((?:^#[^\n]*\n)*)'  # Comentarios opcionales
                r'^(SecRule\s[^"]*"[^"]*"[^"]*"[^"]*")',  # La regla SecRule
                re.MULTILINE
            )

            for match in rule_pattern.finditer(content):
                comments = match.group(1).strip()
                rule_text = match.group(2).strip()

                rule_id = self._extract_rule_id(rule_text)
                if not rule_id:
                    continue

                # Obtener estado de la regla
                rule_state = custom_rules_state.get(rule_id, {})
                current_action = rule_state.get('current_action', 'block')
                enabled = rule_state.get('enabled', True)

                # Extraer descripción de los comentarios
                description = None
                if comments:
                    for line in comments.split('\n'):
                        if line.strip().startswith('#'):
                            comment_text = line.strip()[1:].strip()
                            if comment_text and not comment_text.startswith('=') and 'Custom Rule ID:' not in comment_text:
                                description = comment_text
                                break

                # Crear preview
                preview = rule_text
                if len(preview) > 100:
                    preview = preview[:100] + "..."

                rules.append({
                    "rule_id": rule_id,
                    "rule_text": rule_text,
                    "description": description,
                    "preview": preview,
                    "current_action": current_action,
                    "enabled": enabled,
                    "created_at": rule_state.get('created_at', datetime.now().isoformat()),
                    "last_modified": rule_state.get('last_modified', datetime.now().isoformat())
                })

            return rules

        except Exception as e:
            print(f"Error loading custom rules: {e}")
            return []

    def add_custom_rule(self, rule_text: str, description: str = None) -> bool:
        """Añade una nueva regla personalizada"""
        try:
            # Verificar que la regla tenga un ID
            rule_id = self._extract_rule_id(rule_text)
            if not rule_id:
                raise ValueError("Rule must have a valid ID")

            # Verificar que el ID no esté en uso
            if self.rule_id_exists(rule_id):
                raise ValueError(f"Rule ID {rule_id} already exists")

            # Leer contenido existente
            existing_content = ""
            if os.path.exists(CUSTOM_RULES_FILE):
                with open(CUSTOM_RULES_FILE, 'r') as f:
                    existing_content = f.read()

            # Si el archivo no tiene header, crearlo
            if not existing_content or "CUSTOM MODSECURITY RULES" not in existing_content:
                with open(CUSTOM_RULES_FILE, 'w') as f:
                    f.write(self._get_custom_rules_header())

            # Agregar la nueva regla
            with open(CUSTOM_RULES_FILE, 'a') as f:
                f.write(f"\n# Custom Rule ID: {rule_id}\n")
                if description:
                    f.write(f"# Description: {description}\n")
                f.write(f"# Added: {datetime.now().isoformat()}\n")
                f.write(f"{rule_text}\n\n")

            # Crear estado inicial de la regla
            state = self.load_custom_rules_state()
            state["custom_rules"][rule_id] = {
                "current_action": "block",
                "enabled": True,
                "created_at": datetime.now().isoformat(),
                "last_modified": datetime.now().isoformat(),
                "description": description
            }
            self.save_custom_rules_state(state)

            return True

        except Exception as e:
            print(f"Error adding custom rule: {e}")
            return False

    def rule_id_exists(self, rule_id: str) -> bool:
        """Verifica si un rule ID ya existe (custom rules o core rules)"""
        # Verificar en custom rules
        rules = self.get_all_custom_rules()
        for rule in rules:
            if rule["rule_id"] == rule_id:
                return True

        # Verificar en core rules usando el sistema existente
        try:
            core_rules = load_rules_from_files()
            for rule in core_rules:
                if rule.rule_id == rule_id:
                    return True
        except:
            pass

        return False

    def update_custom_rule_action(self, rule_id: str, action: str) -> bool:
        """Actualiza la acción de una custom rule"""
        try:
            if action not in ['block', 'monitor', 'disabled']:
                raise ValueError(f"Invalid action: {action}")

            state = self.load_custom_rules_state()
            custom_rules = state.get("custom_rules", {})

            if rule_id not in custom_rules:
                # Crear entrada si no existe
                custom_rules[rule_id] = {
                    "current_action": "block",
                    "enabled": True,
                    "created_at": datetime.now().isoformat(),
                    "last_modified": datetime.now().isoformat()
                }

            # Actualizar acción
            custom_rules[rule_id]["current_action"] = action
            custom_rules[rule_id]["enabled"] = action != "disabled"
            custom_rules[rule_id]["last_modified"] = datetime.now().isoformat()

            state["custom_rules"] = custom_rules
            self.save_custom_rules_state(state)

            # Usar el sistema existente de toggle para aplicar los cambios
            if action == "disabled":
                disable_rule(rule_id)
            elif action == "monitor":
                monitor_rule(rule_id)
            elif action == "block":
                enable_rule(rule_id)

            log(f"Custom rule {rule_id} set to {action}")
            return True

        except Exception as e:
            print(f"Error updating custom rule action {rule_id}: {e}")
            return False

    def delete_custom_rule(self, rule_id: str) -> bool:
        """Elimina una regla personalizada - VERSIÓN CORREGIDA"""
        try:
            if not os.path.exists(CUSTOM_RULES_FILE):
                return False

            print(f"Attempting to delete custom rule {rule_id}")

            with open(CUSTOM_RULES_FILE, 'r') as f:
                content = f.read()

            # Patrón mejorado para buscar y remover la regla con sus comentarios
            # Busca desde el comentario "Custom Rule ID: X" hasta la regla SecRule completa
            pattern = rf'(?:^#[^\n]*Custom Rule ID:\s*{rule_id}[^\n]*\n)(?:^#[^\n]*\n)*^SecRule[^\n]*id[:\s]*["\']?{rule_id}["\']?[^"]*"[^\n]*(?:\\\n[^\n]*)*\n*'

            # También intentar patrón alternativo más simple
            if not re.search(pattern, content, re.MULTILINE):
                # Patrón alternativo: buscar cualquier línea que contenga el rule_id
                pattern = rf'^.*id[:\s]*["\']?{rule_id}["\']?.*(?:\\\n.*)*\n*'

            new_content = re.sub(pattern, '', content, flags=re.MULTILINE)

            # Verificar si realmente se eliminó algo
            if new_content == content:
                print(f"Rule {rule_id} not found in file, checking by line scan...")

                # Método alternativo: escanear línea por línea
                lines = content.split('\n')
                new_lines = []
                skip_until_rule_end = False
                found_rule = False

                for line in lines:
                    # Si encontramos una línea que menciona nuestro rule_id
                    if f'id:{rule_id}' in line or f'id:"{rule_id}"' in line or f"id:'{rule_id}" in line:
                        skip_until_rule_end = True
                        found_rule = True
                        continue

                    # Si estamos saltando líneas y encontramos una línea que no termina en \
                    if skip_until_rule_end:
                        if not line.strip().endswith('\\') and line.strip():
                            skip_until_rule_end = False
                        continue

                    # Si no estamos saltando, mantener la línea
                    new_lines.append(line)

                if found_rule:
                    new_content = '\n'.join(new_lines)
                    print(f"Rule {rule_id} found and removed using line scan method")
                else:
                    print(f"Rule {rule_id} not found in custom rules file")
                    # Aún así, limpiar el estado por si acaso
                    state = self.load_custom_rules_state()
                    custom_rules = state.get("custom_rules", {})
                    if rule_id in custom_rules:
                        del custom_rules[rule_id]
                        state["custom_rules"] = custom_rules
                        self.save_custom_rules_state(state)
                        print(f"Removed rule {rule_id} from state file only")
                    return True

            # Escribir el contenido actualizado
            with open(CUSTOM_RULES_FILE, 'w') as f:
                f.write(new_content)

            print(f"Custom rule {rule_id} removed from file")

            # Remover del estado
            state = self.load_custom_rules_state()
            custom_rules = state.get("custom_rules", {})
            if rule_id in custom_rules:
                del custom_rules[rule_id]
                state["custom_rules"] = custom_rules
                self.save_custom_rules_state(state)
                print(f"Removed rule {rule_id} from custom rules state")

            # CORRECCIÓN: Solo limpiar de los estados de toggle si la regla está ahí
            # No llamar enable_rule() automáticamente ya que puede causar problemas
            try:
                # Verificar si la regla está en los estados de toggle antes de intentar limpiarla
                toggle_state = load_state()

                rule_in_disabled = rule_id in toggle_state.get('disabled_rules', {})
                rule_in_monitor = rule_id in toggle_state.get('monitor_rules', {})

                if rule_in_disabled or rule_in_monitor:
                    print(f"Rule {rule_id} found in toggle states, cleaning up...")

                    # Limpiar manualmente de los estados sin llamar enable_rule
                    if rule_in_disabled:
                        del toggle_state['disabled_rules'][rule_id]
                    if rule_in_monitor:
                        del toggle_state['monitor_rules'][rule_id]

                    save_state(toggle_state)

                    # Regenerar archivos de configuración
                    from modsec_rule_toggle import regenerate_disabled_rules_file, regenerate_monitor_rules_file
                    regenerate_disabled_rules_file()
                    regenerate_monitor_rules_file()

                    # Recargar nginx
                    subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
                    print(f"Cleaned rule {rule_id} from toggle states and reloaded nginx")
                else:
                    print(f"Rule {rule_id} not found in toggle states, no cleanup needed")

            except Exception as e:
                print(f"Warning: Could not clean toggle states for rule {rule_id}: {e}")
                # No fallar por esto, la regla ya se eliminó del archivo custom

            log(f"Custom rule {rule_id} deleted successfully")
            return True

        except Exception as e:
            print(f"Error deleting custom rule {rule_id}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_custom_rule(self, rule_id: str) -> dict:
        """Obtiene una custom rule específica"""
        rules = self.get_all_custom_rules()
        for rule in rules:
            if rule["rule_id"] == rule_id:
                return rule
        return None

    def get_statistics(self) -> dict:
        """Obtiene estadísticas de las reglas personalizadas - VERSIÓN CORREGIDA"""
        try:
            rules = self.get_all_custom_rules()
            total = len(rules)

            # Inicializar contadores con valores por defecto
            active = 0
            blocking = 0
            monitoring = 0
            disabled = 0

            # Contar de forma segura
            for rule in rules:
                try:
                    enabled = rule.get("enabled", True)
                    current_action = rule.get("current_action", "block")

                    if enabled:
                        active += 1

                    if current_action == "block" and enabled:
                        blocking += 1
                    elif current_action == "monitor":
                        monitoring += 1
                    elif current_action == "disabled":
                        disabled += 1

                except Exception as e:
                    print(f"Error processing rule {rule.get('rule_id', 'unknown')}: {e}")
                    # Continuar con la siguiente regla
                    continue

            # Calcular reglas recientes (últimos 7 días) de forma segura
            recent = 0
            try:
                from datetime import datetime, timedelta
                seven_days_ago = datetime.now() - timedelta(days=7)

                for rule in rules:
                    try:
                        created_at_str = rule.get("created_at")
                        if created_at_str:
                            # Manejar diferentes formatos de fecha
                            if isinstance(created_at_str, str):
                                # Intentar parsear la fecha
                                try:
                                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                                    if created_at >= seven_days_ago:
                                        recent += 1
                                except ValueError:
                                    # Si falla el parsing, asumir que es reciente si no tiene fecha válida
                                    recent += 1
                            elif isinstance(created_at_str, datetime):
                                if created_at_str >= seven_days_ago:
                                    recent += 1
                    except Exception as e:
                        print(f"Error calculating recent date for rule {rule.get('rule_id', 'unknown')}: {e}")
                        continue

            except Exception as e:
                print(f"Error calculating recent rules: {e}")
                recent = 0

            return {
                "total_custom_rules": total,
                "active_rules": active,
                "blocking_rules": blocking,
                "monitoring_rules": monitoring,
                "disabled_rules": disabled,
                "recent_rules": recent
            }

        except Exception as e:
            print(f"Error in get_statistics: {e}")
            import traceback
            traceback.print_exc()

            # Retornar estadísticas por defecto en caso de error
            return {
                "total_custom_rules": 0,
                "active_rules": 0,
                "blocking_rules": 0,
                "monitoring_rules": 0,
                "disabled_rules": 0,
                "recent_rules": 0
            }

    def debug_rule_existence(self, rule_id: str) -> dict:
        """Debug helper para verificar dónde existe una regla"""
        result = {
            "rule_id": rule_id,
            "in_custom_file": False,
            "in_custom_state": False,
            "in_toggle_disabled": False,
            "in_toggle_monitor": False,
            "file_content_match": False
        }

        try:
            # Verificar en archivo custom
            if os.path.exists(CUSTOM_RULES_FILE):
                with open(CUSTOM_RULES_FILE, 'r') as f:
                    content = f.read()
                    if f'id:{rule_id}' in content or f'id:"{rule_id}"' in content or f"id:'{rule_id}'" in content:
                        result["in_custom_file"] = True
                        result["file_content_match"] = True

            # Verificar en estado custom
            state = self.load_custom_rules_state()
            if rule_id in state.get("custom_rules", {}):
                result["in_custom_state"] = True

            # Verificar en estados de toggle
            try:
                toggle_state = load_state()
                if rule_id in toggle_state.get("disabled_rules", {}):
                    result["in_toggle_disabled"] = True
                if rule_id in toggle_state.get("monitor_rules", {}):
                    result["in_toggle_monitor"] = True
            except:
                pass

        except Exception as e:
            result["error"] = str(e)

        return result

    def cleanup_orphaned_custom_rules(self) -> dict:
        """Limpia reglas custom huérfanas en diferentes estados"""
        cleanup_result = {
            "cleaned_from_state": [],
            "cleaned_from_toggle": [],
            "errors": []
        }

        try:
            # Obtener reglas que realmente existen en el archivo
            existing_rules = set()
            if os.path.exists(CUSTOM_RULES_FILE):
                with open(CUSTOM_RULES_FILE, 'r') as f:
                    content = f.read()
                    # Buscar todos los rule IDs en el archivo
                    matches = re.findall(r'id[:=]["\']?(\d+)["\']?', content)
                    existing_rules.update(matches)

            # Limpiar del estado custom
            state = self.load_custom_rules_state()
            custom_rules = state.get("custom_rules", {})
            rules_to_remove = []

            for rule_id in custom_rules.keys():
                if rule_id not in existing_rules:
                    rules_to_remove.append(rule_id)

            for rule_id in rules_to_remove:
                del custom_rules[rule_id]
                cleanup_result["cleaned_from_state"].append(rule_id)

            if rules_to_remove:
                state["custom_rules"] = custom_rules
                self.save_custom_rules_state(state)

            # Limpiar de estados de toggle
            try:
                toggle_state = load_state()
                toggle_cleaned = []

                # Limpiar disabled rules
                disabled_to_remove = []
                for rule_id in toggle_state.get("disabled_rules", {}).keys():
                    if rule_id not in existing_rules and rule_id.startswith('9'):  # Custom rules generalmente 9XXXX
                        disabled_to_remove.append(rule_id)

                for rule_id in disabled_to_remove:
                    del toggle_state["disabled_rules"][rule_id]
                    toggle_cleaned.append(rule_id)

                # Limpiar monitor rules
                monitor_to_remove = []
                for rule_id in toggle_state.get("monitor_rules", {}).keys():
                    if rule_id not in existing_rules and rule_id.startswith('9'):  # Custom rules generalmente 9XXXX
                        monitor_to_remove.append(rule_id)

                for rule_id in monitor_to_remove:
                    del toggle_state["monitor_rules"][rule_id]
                    toggle_cleaned.append(rule_id)

                if toggle_cleaned:
                    save_state(toggle_state)
                    cleanup_result["cleaned_from_toggle"] = toggle_cleaned

            except Exception as e:
                cleanup_result["errors"].append(f"Error cleaning toggle states: {e}")

        except Exception as e:
            cleanup_result["errors"].append(f"Error in cleanup: {e}")

        return cleanup_result

# Instancia global del gestor de exclusiones
exclusion_manager = ExclusionManager()

# Instancia global del gestor de reglas personalizadas
custom_rules_manager = CustomRulesManager()

def parse_modsecurity_logs(file_path):
    """
    Parsea los logs completos de ModSecurity y devuelve
    una lista de entradas, cada una con sus secciones extraídas.
    """
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as file:
            text = file.read()
    except (IOError, FileNotFoundError) as e:
        print(f"Error reading log file: {e}")
        return []

    # Expresión regular que captura cada bloque
    entry_re = re.compile(
        r'---(?P<id>[^-]+)---A--\r?\n'
        r'(?P<A>.*?)\r?\n'
        r'---(?P=id)---B--\r?\n'
        r'(?P<B>.*?)\r?\n'
        r'(?:'                          # <-- Hacer opcional todo el bloque E
            r'---(?P=id)---E--\r?\n'
            r'(?P<E>.*?)\r?\n'
        r')?'
        r'---(?P=id)---F--\r?\n'
        r'(?P<F>.*?)'
        r'(?:\r?\n---(?P=id)---H--\r?\n(?P<H>.*?))?'
        r'\r?\n---(?P=id)---Z--',
        re.DOTALL
    )
    logs = []
    for m in entry_re.finditer(text):
        # ---- Bloque A ----
        parts = m.group('A')
        match = re.match(r'\[(?P<timestamp>.*?)\] (?P<unique_id>\S+) (?P<client_ip>\S+) (?P<client_port>\S+) (?P<server_ip>\S+) (?P<server_port>\S+)', parts)
        if match:
            timestamp = datetime.strptime(match.group('timestamp'), "%d/%b/%Y:%H:%M:%S %z")
            unique_id = match.group('unique_id')
            client_ip = match.group('client_ip')
            client_port = match.group('client_port')
            server_ip = match.group('server_ip')
            server_port = match.group('server_port')
        # ---- Bloque B: Request ----
        request_lines = m.group('B').splitlines()
        if request_lines:
            method_uri_version = request_lines[0].split()
            request_method = method_uri_version[0]
            request_uri = method_uri_version[1] if len(method_uri_version) > 1 else ''
            # Headers: resto de líneas hasta primera línea vacía
            request_headers = {}
            for line in request_lines[1:]:
                if not line.strip():
                    break
                if ':' in line:
                    key, val = line.split(':', 1)
                    request_headers[key.strip()] = val.strip()
        else:
            request_method = request_uri = ''
            request_headers = {}

        # ---- Bloque E: Body ----
        body_section = m.group('E').strip() if m.group('E') else ''

        # ---- Bloque F: Response ----
        response_section = m.group('F')
        status_code = None
        response_headers = {}
        if response_section:
            lines = response_section.splitlines()
            if lines:
                # Primera línea: "HTTP/1.1 403 Forbidden"
                status_parts = lines[0].split()
                if len(status_parts) >= 2 and status_parts[0].startswith("HTTP/"):
                    status_code = int(status_parts[1])
                # Headers: hasta primera línea vacía
                for line in lines[1:]:
                    if not line.strip():
                        break
                    if ':' in line:
                        k, v = line.split(':', 1)
                        response_headers[k.strip()] = v.strip()

        # ---- Bloque H: Alertas ----
        alert_section = m.group('H').strip()
        rule_messages = []
        for line in alert_section.splitlines():
            # omite líneas vacías
            file_match    = re.search(r'\[file\s+"([^"]+)"\]', line)
            line_match    = re.search(r'\[line\s+"(\d+)"\]', line)
            id_match      = re.search(r'\[id\s+"(\d+)"\]', line)
            msg_match     = re.search(r'\[msg\s+"([^"]+)"\]', line)
            data_match    = re.search(r'\[data\s+"([^"]*)"\]', line)
            sev_match     = re.search(r'\[severity\s+"(\d+)"\]', line)
            tags_matches  = re.findall(r'\[tag\s+"([^"]+)"\]', line)
            host_match    = re.search(r'\[hostname\s+"([^"]+)"\]', line)

        # Construimos la entrada solo si encontramos los campos básicos
            if file_match and line_match and id_match and msg_match and sev_match and host_match:
                rule_messages.append({
                    "modsec_files"    : file_match.group(1),
                    "modsec_lines"    : int(line_match.group(1)),
                    "rule_id"      : int(id_match.group(1)),
                    "rule_msg" : msg_match.group(1),
                    "rule_data" : data_match.group(1),
                    "rule_severity" : int(sev_match.group(1)),
                    "rule_tags"     : tags_matches,
                    "modsec_hostname" : host_match.group(1)
                    })

        entry = {
            "timestamp": timestamp,
            "id": unique_id,
            "ip_address": client_ip,
            "port": client_port,
            "method": request_method,
            "path": request_uri,
            "status": status_code,
            "server_ip": server_ip,
            "server_port": server_port,
            "response_headers": response_headers,
            "rule_messages": rule_messages
        }
        logs.append(entry)
    return logs

def filter_logs(log_type: str, rule_filter: Optional[str], severity_filter: Optional[str]) -> List[dict]:
    entries = LOG_ENTRIES  # LOG_ENTRIES ahora es lista de dicts

    # Filtrado por tipo de log usando 'status_code'
    if log_type == "normal":
        entries = [e for e in entries if (200 <= e['status'] <= 399) or e['status'] in (401, 404)]
    elif log_type == "blocked":
        entries = [e for e in entries if e['status'] in (406, 414)]
    elif log_type == "attack":
        entries = [e for e in entries if e['status'] == 403]
    elif log_type != "total":
        raise HTTPException(status=400, detail="Invalid log type")

    # Filtrado por regla
    if rule_filter:
        entries = [
            e for e in entries if any(
                rule_filter.lower() in (msg.get('rule_msg', '').lower()) or
                rule_filter.lower() in (msg.get('rule_data', '').lower())
                for msg in e.get('rule_messages', [])
            )
        ]

    # Filtrado por severidad
    if severity_filter:
        entries = [
            e for e in entries if any(
                severity_filter.lower() in (msg.get('rule_severity', '').lower())
                for msg in e.get('rule_messages', [])
            )
        ]

    # Ordenar por timestamp (ya convertido a datetime)
    return sorted(entries, key=lambda x: x.get('timestamp'), reverse=True)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    global LOG_ENTRIES
    LOG_ENTRIES = parse_modsecurity_logs(LOG_FILE_PATH)  # Parse on each request (refresh)

    total_requests = len(LOG_ENTRIES)
    blocked_requests = len([entry for entry in LOG_ENTRIES if entry['status'] in (406, 414)])
    attack_attempts = len([entry for entry in LOG_ENTRIES if entry['status'] == 403])
    normal_traffic = total_requests - blocked_requests - attack_attempts

    recent_logs = sorted(LOG_ENTRIES, key=lambda x: x['timestamp'], reverse=True)[:50]

    status_data = {}
    for entry in LOG_ENTRIES:
        if entry['status'] is not None:
            status_data[entry['status']] = status_data.get(entry['status'], 0) + 1
    status_data = [{"status": str(k), "count": v} for k, v in status_data.items()]

    hourly = {}
    for entry in LOG_ENTRIES:
        hour = entry['timestamp'].hour
        hourly[hour] = hourly.get(hour, 0) + 1
    hourly_data = [{"hour": h, "count": c} for h, c in hourly.items()]

    ip_counts = {}
    for entry in LOG_ENTRIES:
        ip_counts[entry['ip_address']] = ip_counts.get(entry['ip_address'], 0) + 1
    top_ips_data = [{"ip": ip, "count": count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "normal_traffic": normal_traffic,
        "blocked_requests": blocked_requests,
        "attack_attempts": attack_attempts,
        "recent_logs": recent_logs,
        "status_data": sorted(status_data, key=lambda x: x["status"]),
        "hourly_data": sorted(hourly_data, key=lambda x: x["hour"]),
        "top_ips": top_ips_data,
        "now": datetime.now()
    })

@app.get("/logs/{log_type}", response_class=HTMLResponse)
async def logs_page(
    request: Request,
    log_type: str,
    page: int = 1,
    rule_filter: Optional[str] = None,
    severity_filter: Optional[str] = None
):
    global LOG_ENTRIES
    LOG_ENTRIES = parse_modsecurity_logs(LOG_FILE_PATH)
    entries = filter_logs(log_type, rule_filter, severity_filter)
    total_entries = len(entries)
    total_pages = max(1, (total_entries + PER_PAGE - 1) // PER_PAGE)
    page = max(1, min(page, total_pages))

    paginated = entries[(page - 1) * PER_PAGE: page * PER_PAGE]

    title_map = {
        "normal": "Normal Traffic",
        "blocked": "Blocked Requests",
        "attack": "Attack Attempts",
        "total": "Total Requests"
    }
    title = title_map.get(log_type, "Unknown Log Type")

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "entries": paginated,
        "page": page,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "log_type": log_type,
        "title": title,
        "total_pages": total_pages,
        "rule_filter": rule_filter,
        "severity_filter": severity_filter
    })

class UpdateActionRequest(BaseModel):
    action: RuleAction

# === Rule Management Logic (UPDATED) ===

def load_rule_states():
    """Carga los estados de las reglas desde el archivo de estado"""
    try:
        with open(RULE_STATE_FILE, 'r') as f:
            state = json.load(f)
            # Ensure both keys exist for backward compatibility
            if "monitor_rules" not in state:
                state["monitor_rules"] = {}
            if "disabled_rules" not in state:
                state["disabled_rules"] = {}
            return state
    except (FileNotFoundError, json.JSONDecodeError):
        return {"disabled_rules": {}, "monitor_rules": {}}

def get_rule_current_action(rule_id: str) -> RuleAction:
    """Determina la acción actual de una regla basada en su estado"""
    # Primero verificar cambios pendientes
    if rule_id in PENDING_RULE_UPDATES:
        return PENDING_RULE_UPDATES[rule_id]

    # Cargar estados guardados
    states = load_rule_states()

    if rule_id in states.get("disabled_rules", {}):
        return RuleAction.DISABLED
    elif rule_id in states.get("monitor_rules", {}):
        return RuleAction.MONITOR
    else:
        return RuleAction.BLOCK

def load_rules_from_files(log_msg_map: Dict[str, str] = None) -> List[ModSecRule]:
    """
    Load ModSecurity rules from files, handling both traditional and shorthand formats.
    Now includes proper state detection for monitor/disabled rules.
    """
    rules = []
    rule_files = glob.glob(RULE_FILES_GLOB)

    # Excluir archivos de gestión personalizada
    excluded_files = [
        "RESPONSE-999-CUSTOM-RULES.conf",
        "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
    ]

    rule_files = [f for f in rule_files if not any(excl in f for excl in excluded_files)]

    # Load current rule states
    rule_states = load_rule_states()
    disabled_rules = rule_states.get("disabled_rules", {})
    monitor_rules = rule_states.get("monitor_rules", {})

    found_rule_ids = set()

    for file_path in rule_files:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Normalize line endings and split into lines
        lines = content.replace('\r\n', '\n').split('\n')

        active_rules_text = []
        disabled_rules_in_file = []
        current_rule_lines = []
        collecting_rule = False
        is_disabled_rule = False
        is_shorthand_format = False

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                if current_rule_lines:
                    current_rule_lines.append(line)
                continue

            # Handle both traditional and shorthand rule formats
            if not collecting_rule:
                # Check for traditional SecRule format (commented or active)
                if re.match(r'^\s*#.*SecRule', line):
                    is_disabled_rule = True
                    current_rule_lines = [line]
                    collecting_rule = True
                elif re.match(r'^\s*SecRule', line):
                    is_disabled_rule = False
                    current_rule_lines = [line]
                    collecting_rule = True
                # Check for shorthand rule format (starts with id:)
                elif re.match(r'^\s*#?\s*id:\d+', line):
                    is_shorthand_format = True
                    is_disabled_rule = line.lstrip().startswith('#')
                    current_rule_lines = [line]
                    collecting_rule = True
                continue

            # If we're collecting a rule
            if collecting_rule:
                current_rule_lines.append(line)

                # For traditional SecRule format, check for line continuation
                if not is_shorthand_format:
                    if not line.rstrip().endswith('\\'):
                        collecting_rule = False
                # For shorthand format, check for rule end (no comma at end)
                else:
                    if not line.rstrip().endswith(','):
                        collecting_rule = False

                # When we finish collecting a complete rule
                if not collecting_rule:
                    rule_block = '\n'.join(current_rule_lines)
                    rule_id_match = re.search(r'id:(\d+)', rule_block)

                    if rule_id_match:
                        rule_id = rule_id_match.group(1)
                        if is_disabled_rule:
                            disabled_rules_in_file.append((rule_id, rule_block, file_path))
                        else:
                            active_rules_text.append((rule_id, rule_block, file_path))

                    # Reset state for next rule
                    current_rule_lines = []
                    is_disabled_rule = False
                    is_shorthand_format = False

        # Process active rules
        for rule_id, rule_text, file_path in active_rules_text:
            if rule_id in found_rule_ids:
                continue

            found_rule_ids.add(rule_id)

            # Extract description from msg or use rule text
            msg_match = re.search(r"msg:'([^']+)'", rule_text) or re.search(r'msg:"([^"]+)"', rule_text)
            description = log_msg_map.get(rule_id) if log_msg_map else None
            description = description or msg_match.group(1) if msg_match else rule_text

            filename = Path(file_path).stem
            category = filename.split('-')[1] if '-' in filename else "General"

            # Extract severity (supporting both single and double quotes)
            severity_match = re.search(r"severity:\s*['\"](?P<severity>\w+)['\"]", rule_text, re.IGNORECASE)
            severity = severity_match.group("severity").upper() if severity_match else None

            # Determine current action based on state files
            current_action = get_rule_current_action(rule_id)

            rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=filename,
                description=description,
                default_action=RuleAction.BLOCK,
                current_action=current_action,
                severity=severity,
                category=category
            ))

        # Process disabled rules (from file comments)
        for rule_id, rule_text, file_path in disabled_rules_in_file:
            if rule_id in found_rule_ids:
                continue

            msg_match = re.search(r"msg:'([^']+)'", rule_text) or re.search(r'msg:"([^"]+)"', rule_text)
            description = msg_match.group(1) if msg_match else rule_text
            filename = Path(file_path).stem
            category = filename.split('-')[1] if '-' in filename else "General"

            severity_match = re.search(r"severity:\s*['\"](?P<severity>\w+)['\"]", rule_text, re.IGNORECASE)
            severity = severity_match.group("severity").upper() if severity_match else None

            rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=filename,
                description=description,
                default_action=RuleAction.BLOCK,
                current_action=RuleAction.DISABLED,
                severity=severity,
                category=category
            ))
            found_rule_ids.add(rule_id)

    # Add any rules that are only in the state file (rules that were disabled/monitored programmatically)
    all_state_rules = set(disabled_rules.keys()) | set(monitor_rules.keys())
    for rule_id in all_state_rules:
        if rule_id not in found_rule_ids:
            # This is a rule that exists only in state file
            rule_info = disabled_rules.get(rule_id) or monitor_rules.get(rule_id, {})
            filename = rule_info.get('file', 'unknown')

            current_action = RuleAction.DISABLED if rule_id in disabled_rules else RuleAction.MONITOR

            rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=filename,
                description=f"Rule {rule_id} (state-tracked only)",
                default_action=RuleAction.BLOCK,
                current_action=current_action,
                severity=None,
                category="Unknown"
            ))

    print(f"\nDEBUG: Rule loading complete. Total rules: {len(rules)}")
    print(f"  Active: {len([r for r in rules if r.current_action == RuleAction.BLOCK])}")
    print(f"  Monitor: {len([r for r in rules if r.current_action == RuleAction.MONITOR])}")
    print(f"  Disabled: {len([r for r in rules if r.current_action == RuleAction.DISABLED])}")

    return rules

def find_rule_by_id(rule_id: str) -> ModSecRule:
    for rule in load_rules_from_files():
        if rule.rule_id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail="Rule not found")

def update_rule_config(rule_id: str, action: RuleAction):
    PENDING_RULE_UPDATES[rule_id] = action

def apply_config_changes():
    """Aplica los cambios de configuración pendientes usando el sistema mejorado"""
    success_updates = []
    failed_updates = []

    for raw_rule_id, raw_action in PENDING_RULE_UPDATES.items():
        rule_id = str(raw_rule_id).strip()
        action = raw_action.strip().lower() if isinstance(raw_action, str) else raw_action.value

        if action not in ("block", "monitor", "disabled"):
            print(f"Invalid action '{action}' for rule {rule_id}")
            failed_updates.append(rule_id)
            continue

        try:
            if action == "disabled":
                print(f"Disabling rule {rule_id}")
                disable_rule(rule_id)
            elif action == "block":
                print(f"Enabling rule {rule_id} (block mode)")
                enable_rule(rule_id)
            elif action == "monitor":
                print(f"Setting rule {rule_id} to monitor mode")
                monitor_rule(rule_id)

            print(f"Successfully set rule {rule_id} to {action}")
            success_updates.append(rule_id)

        except Exception as e:
            print(f"Failed to {action} rule {rule_id}: {e}")
            failed_updates.append(rule_id)

    PENDING_RULE_UPDATES.clear()

    if failed_updates:
        raise HTTPException(
            status_code=207,
            detail={
                "message": "Some rule changes failed",
                "updated": success_updates,
                "failed": failed_updates
            }
        )

    return {"status": "success", "updated": success_updates}

# === API Routes ===
@app.get("/api/rules", response_model=List[ModSecRule])
async def get_all_rules():
    log_msg_map = extract_rule_descriptions_from_log(LOG_FILE_PATH)
    return load_rules_from_files(log_msg_map)

@app.get("/api/rules/statistics")
async def get_rules_statistics():
    """Obtiene estadísticas de las reglas"""
    try:
        # Ejecutar limpieza de reglas huérfanas antes de obtener estadísticas
        cleanup_orphaned_rules()

        rules = load_rules_from_files()

        stats = {
            "total": len(rules),
            "active": len([r for r in rules if r.current_action == RuleAction.BLOCK]),
            "monitor": len([r for r in rules if r.current_action == RuleAction.MONITOR]),
            "disabled": len([r for r in rules if r.current_action == RuleAction.DISABLED]),
            "by_category": {},
            "by_severity": {}
        }

        for rule in rules:
            # Por categoría
            category = rule.category
            if category not in stats["by_category"]:
                stats["by_category"][category] = {"total": 0, "active": 0, "monitor": 0, "disabled": 0}

            stats["by_category"][category]["total"] += 1
            if rule.current_action == RuleAction.BLOCK:
                stats["by_category"][category]["active"] += 1
            elif rule.current_action == RuleAction.MONITOR:
                stats["by_category"][category]["monitor"] += 1
            elif rule.current_action == RuleAction.DISABLED:
                stats["by_category"][category]["disabled"] += 1

            # Por severidad
            severity = rule.severity or "Unknown"
            if severity not in stats["by_severity"]:
                stats["by_severity"][severity] = {"total": 0, "active": 0, "monitor": 0, "disabled": 0}

            stats["by_severity"][severity]["total"] += 1
            if rule.current_action == RuleAction.BLOCK:
                stats["by_severity"][severity]["active"] += 1
            elif rule.current_action == RuleAction.MONITOR:
                stats["by_severity"][severity]["monitor"] += 1
            elif rule.current_action == RuleAction.DISABLED:
                stats["by_severity"][severity]["disabled"] += 1

        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting statistics: {str(e)}")

@app.get("/api/rules/{rule_id}", response_model=ModSecRule)
async def get_rule(rule_id: str):
    return find_rule_by_id(rule_id)

@app.post("/api/rules/{rule_id}/action")
async def update_rule_action(rule_id: str, req: UpdateActionRequest):
    try:
        print(f"Received POST request to update rule {rule_id} with action: {req.action}")

        update_rule_config(rule_id, req.action)

        # Apply the config changes immediately
        result = apply_config_changes()

        return {
            "message": f"Rule {rule_id} successfully updated to '{req.action}'",
            "apply_result": result
        }

    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found: {e}"
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action for rule {rule_id}: {e}"
        )

    except HTTPException as e:
        # If apply_config_changes raises HTTPException, propagate it
        raise e

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error while updating rule {rule_id}: {str(e)}"
        )

@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    return templates.TemplateResponse("rules_management.html", {"request": request})

# === CUSTOM RULES API ENDPOINTS ===

@app.get("/api/rules/custom/list")
async def list_custom_rules():
    """Lista todas las reglas personalizadas - VERSIÓN CORREGIDA"""
    try:
        rules = custom_rules_manager.get_all_custom_rules()
        return {"rules": rules}

    except Exception as e:
        print(f"Error listing custom rules: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error listing custom rules: {str(e)}")

@app.get("/api/rules/custom/statistics")
async def get_custom_rules_statistics():
    """Obtiene estadísticas detalladas de reglas personalizadas"""
    try:
        stats = custom_rules_manager.get_statistics()

        # Obtener distribución por estados
        rules = custom_rules_manager.get_all_custom_rules()
        by_action = {}
        by_status = {"enabled": 0, "disabled": 0}

        for rule in rules:
            action = rule.get("current_action", "block")
            by_action[action] = by_action.get(action, 0) + 1

            status = "enabled" if rule.get("enabled", True) else "disabled"
            by_status[status] += 1

        stats.update({
            "by_action": by_action,
            "by_status": by_status,
            "rules_detail": rules if len(rules) <= 10 else rules[:10]  # Incluir detalle si hay pocas reglas
        })

        return stats

    except Exception as e:
        print(f"Error getting custom rules statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting statistics: {str(e)}")

@app.get("/api/rules/custom/{rule_id}")
async def get_custom_rule(rule_id: str):
    """Obtiene una custom rule específica"""
    try:
        rule = custom_rules_manager.get_custom_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Custom rule not found")
        return rule
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching custom rule: {str(e)}")

@app.post("/api/rules/custom/{rule_id}/action")
async def update_custom_rule_action(rule_id: str, req: UpdateActionRequest):
    """Actualiza la acción de una custom rule"""
    try:
        print(f"Received request to update custom rule {rule_id} with action: {req.action}")

        # Verificar que la regla existe antes de intentar eliminarla
        rule = custom_rules_manager.get_custom_rule(rule_id)
        if not rule:
            print(f"Custom rule {rule_id} not found")
            raise HTTPException(status_code=404, detail="Custom rule not found")

        # Actualizar la acción
        success = custom_rules_manager.update_custom_rule_action(rule_id, req.action.value)

        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update custom rule {rule_id} action"
            )

        return {
            "message": f"Custom rule {rule_id} successfully updated to '{req.action}'",
            "rule_id": rule_id,
            "new_action": req.action.value
        }

    except HTTPException as e:
        raise e
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action for custom rule {rule_id}: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error while updating custom rule {rule_id}: {str(e)}"
        )

@app.post("/api/rules/custom/{rule_id}/toggle")
async def toggle_custom_rule(rule_id: str):
    """Habilita/deshabilita una custom rule"""
    try:
        rule = custom_rules_manager.get_custom_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Custom rule not found")

        # Determinar nueva acción
        current_action = rule.get("current_action", "block")
        new_action = "disabled" if current_action != "disabled" else "block"

        success = custom_rules_manager.update_custom_rule_action(rule_id, new_action)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to toggle custom rule")

        action_text = "disabled" if new_action == "disabled" else "enabled"
        return {
            "message": f"Custom rule {rule_id} {action_text} successfully",
            "rule_id": rule_id,
            "new_action": new_action
        }

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error toggling custom rule {rule_id}: {str(e)}"
        )

@app.delete("/api/rules/custom/{rule_id}")
async def delete_custom_rule(rule_id: str):
    """Elimina una regla personalizada - VERSIÓN CORREGIDA"""
    try:
        print(f"DELETE request received for custom rule: {rule_id}")

        # Verificar que la regla existe antes de intentar eliminarla
        rule = custom_rules_manager.get_custom_rule(rule_id)
        if not rule:
            print(f"Custom rule {rule_id} not found")
            raise HTTPException(status_code=404, detail="Custom rule not found")

        print(f"Found custom rule {rule_id}, proceeding with deletion")

        # Intentar eliminar la regla
        success = custom_rules_manager.delete_custom_rule(rule_id)

        if success:
            print(f"Custom rule {rule_id} deleted successfully")

            # Intentar recargar nginx, pero no fallar si no se puede
            try:
                result = subprocess.run(['systemctl', 'reload', 'nginx'],
                                      check=True, capture_output=True, text=True, timeout=10)
                print("Nginx reloaded successfully after rule deletion")
            except subprocess.TimeoutExpired:
                print("Warning: Nginx reload timed out, but rule was deleted")
            except subprocess.CalledProcessError as e:
                print(f"Warning: Nginx reload failed: {e.stderr}, but rule was deleted")
            except Exception as e:
                print(f"Warning: Could not reload nginx: {e}, but rule was deleted")

            return {"message": f"Custom rule {rule_id} deleted successfully"}
        else:
            print(f"Failed to delete custom rule {rule_id}")
            raise HTTPException(status_code=500, detail="Failed to delete custom rule")

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        print(f"Unexpected error deleting custom rule {rule_id}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error deleting custom rule: {str(e)}"
        )

@app.put("/api/rules/custom/{rule_id}")
async def update_custom_rule_metadata(rule_id: str, request: dict):
    """Actualiza metadatos de una custom rule (descripción, etc.)"""
    try:
        rule = custom_rules_manager.get_custom_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Custom rule not found")

        # Por ahora solo soportamos actualizar el estado
        # En el futuro se puede extender para actualizar descripción

        success = True  # Placeholder

        if success:
            return {"message": "Custom rule updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update custom rule")

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error updating custom rule {rule_id}: {str(e)}"
        )

# Endpoint para obtener el estado actual de una custom rule
@app.get("/api/rules/custom/{rule_id}/status")
async def get_custom_rule_status(rule_id: str):
    """Obtiene el estado actual de una custom rule"""
    try:
        rule = custom_rules_manager.get_custom_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Custom rule not found")

        return {
            "rule_id": rule_id,
            "current_action": rule.get("current_action", "block"),
            "enabled": rule.get("enabled", True),
            "last_modified": rule.get("last_modified"),
            "description": rule.get("description")
        }

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error getting custom rule status: {str(e)}"
        )

# Endpoint para validar un rule ID antes de crear una regla
@app.get("/api/rules/validate/{rule_id}")
async def validate_rule_id(rule_id: str):
    """Valida si un rule ID está disponible"""
    try:
        exists = custom_rules_manager.rule_id_exists(rule_id)
        return {
            "rule_id": rule_id,
            "available": not exists,
            "exists_in": "custom_rules" if exists else None
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error validating rule ID: {str(e)}"
        )

@app.post("/api/rules/custom/cleanup")
async def cleanup_custom_rules():
    """Limpia reglas personalizadas corruptas o duplicadas"""
    try:
        if not os.path.exists(CUSTOM_RULES_FILE):
            return {"message": "No custom rules file found"}

        # Hacer backup del archivo original
        backup_file = CUSTOM_RULES_FILE + f".backup.{int(datetime.now().timestamp())}"
        shutil.copy2(CUSTOM_RULES_FILE, backup_file)

        # Obtener reglas válidas
        valid_rules = custom_rules_manager.get_all_custom_rules()

        # Reescribir el archivo con solo las reglas válidas
        with open(CUSTOM_RULES_FILE, 'w') as f:
            f.write(custom_rules_manager._get_custom_rules_header())

            for i, rule in enumerate(valid_rules, 1):
                f.write(f"\n# Custom Rule {i}\n")
                f.write(f"# Cleaned: {datetime.now().isoformat()}\n")
                if rule.get('description'):
                    f.write(f"# Description: {rule['description']}\n")
                f.write(f"{rule['rule_text']}\n\n")

        # Recargar nginx
        try:
            subprocess.run(['systemctl', 'reload', 'nginx'], check=True, timeout=10)
        except Exception as e:
            print(f"Warning: Could not reload nginx: {e}")

        return {
            "message": f"Cleaned up custom rules file. Found {len(valid_rules)} valid rules.",
            "backup_file": backup_file,
            "rules_found": len(valid_rules)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error cleaning up rules: {str(e)}")

@app.post("/api/rules/custom")
async def save_custom_rule_api(request: dict):
    """Guarda una regla personalizada"""
    try:
        rule_text = request.get("rule", "")
        description = request.get("description", "")

        if not rule_text:
            raise HTTPException(status_code=400, detail="Rule text is required")

        print(f"Saving custom rule: {rule_text}")

        # Usar el manager para añadir la regla
        success = custom_rules_manager.add_custom_rule(rule_text, description)

        if not success:
            raise HTTPException(status_code=400, detail="Failed to save rule")

        # Recargar nginx
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "reload", "nginx"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"Nginx reload failed: {result.stderr}")
                return {
                    "status": "partial_success",
                    "message": "Rule saved but nginx reload failed. Please reload manually.",
                    "nginx_error": result.stderr
                }

        except subprocess.TimeoutExpired:
            return {
                "status": "partial_success",
                "message": "Rule saved but nginx reload timed out"
            }
        except Exception as e:
            print(f"Error reloading nginx: {e}")
            return {
                "status": "partial_success",
                "message": f"Rule saved but nginx reload failed: {str(e)}"
            }

        return {
            "status": "success",
            "message": "Custom rule added and nginx reloaded successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error saving custom rule: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error saving custom rule: {str(e)}")

# Legacy endpoint for compatibility
@app.post("/rules/custom")
async def save_custom_rule_legacy(rule_data: dict):
    """Legacy endpoint for saving custom rules"""
    try:
        rule_text = rule_data.get('rule_text', '')
        if not rule_text:
            raise HTTPException(status_code=400, detail="Rule text is required")

        success = custom_rules_manager.add_custom_rule(rule_text)

        if not success:
            raise HTTPException(status_code=400, detail="Failed to save rule")

        # Recargar nginx
        result = subprocess.run(["sudo", "systemctl", "reload", "nginx"],
                               capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Nginx reload failed: {result.stderr.strip()}")

        return {"status": "success", "message": "Custom rule added and nginx reloaded"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving custom rule: {str(e)}")

# Endpoints para debugging
@app.get("/api/rules/custom/{rule_id}/debug")
async def debug_custom_rule(rule_id: str):
    """Debug endpoint para verificar estado de una custom rule"""
    try:
        debug_info = custom_rules_manager.debug_rule_existence(rule_id)
        return debug_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Debug error: {str(e)}")

@app.post("/api/rules/custom/cleanup")
async def cleanup_custom_rules():
    """Endpoint para limpiar reglas custom huérfanas"""
    try:
        result = custom_rules_manager.cleanup_orphaned_custom_rules()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cleanup error: {str(e)}")

# === ENDPOINTS DE EXCLUSIONES (ORDEN CORRECTO) ===

@app.get("/api/exclusions", response_model=List[ExclusionRule])
async def get_exclusions():
    """Obtiene todas las exclusiones"""
    try:
        return exclusion_manager.get_all_exclusions()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading exclusions: {str(e)}")

# ESTADÍSTICAS - ESPECÍFICO (va ANTES que {exclusion_id})
@app.get("/api/exclusions/statistics")
async def get_exclusion_statistics():
    """Obtiene estadísticas de las exclusiones"""
    try:
        exclusions = exclusion_manager.get_all_exclusions()

        stats = {
            "total": len(exclusions),
            "enabled": len([ex for ex in exclusions if ex.enabled]),
            "disabled": len([ex for ex in exclusions if not ex.enabled]),
            "by_type": {},
            "by_condition": {},
            "recent": len([ex for ex in exclusions if
                         (datetime.now() - ex.created_at).days <= 7])
        }

        for exclusion in exclusions:
            ex_type = exclusion.exclusion_type
            stats["by_type"][ex_type] = stats["by_type"].get(ex_type, 0) + 1

            condition = exclusion.condition_variable
            stats["by_condition"][condition] = stats["by_condition"].get(condition, 0) + 1

        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting statistics: {str(e)}")

# PLANTILLAS - ESPECÍFICO (va ANTES que {exclusion_id})
@app.get("/api/exclusions/templates/common")
async def get_common_exclusion_templates():
    """Obtiene plantillas comunes de exclusiones"""
    templates = [
        {
            "name": "Excluir regla por URI específica",
            "description": "Deshabilita una regla específica para una URL concreta",
            "template": {
                "condition_variable": "REQUEST_URI",
                "operator": "@beginsWith",
                "condition_value": "/api/",
                "exclusion_type": "ruleRemoveById",
                "exclusion_value": "942100",
                "phase": 2
            }
        },
        {
            "name": "Excluir parámetro de reglas SQL injection",
            "description": "Excluye un parámetro específico de las reglas de SQL injection",
            "template": {
                "condition_variable": "REQUEST_URI",
                "operator": "@beginsWith",
                "condition_value": "/admin/",
                "exclusion_type": "ruleRemoveTargetByTag",
                "exclusion_value": "attack-sqli",
                "target": "ARGS:search",
                "phase": 2
            }
        },
        {
            "name": "Deshabilitar WAF para IP confiable",
            "description": "Deshabilita completamente ModSecurity para una IP específica",
            "template": {
                "condition_variable": "REMOTE_ADDR",
                "operator": "@ipMatch",
                "condition_value": "192.168.1.100",
                "exclusion_type": "ruleEngine=Off",
                "exclusion_value": "",
                "phase": 1
            }
        },
        {
            "name": "Excluir User-Agent de escáneres",
            "description": "Excluye ciertos User-Agents de las reglas de detección",
            "template": {
                "condition_variable": "REQUEST_HEADERS:User-Agent",
                "operator": "@contains",
                "condition_value": "scanner",
                "exclusion_type": "ruleRemoveByTag",
                "exclusion_value": "attack-generic",
                "phase": 1
            }
        },
        {
            "name": "Excluir WordPress admin",
            "description": "Deshabilita reglas específicas para el admin de WordPress",
            "template": {
                "condition_variable": "REQUEST_URI",
                "operator": "@beginsWith",
                "condition_value": "/wp-admin/",
                "exclusion_type": "ruleRemoveTargetByTag",
                "exclusion_value": "attack-xss",
                "target": "ARGS:content",
                "phase": 2
            }
        }
    ]

    return {"templates": templates}

# INDIVIDUAL - GENERAL (va DESPUÉS de las rutas específicas)
@app.get("/api/exclusions/{exclusion_id}", response_model=ExclusionRule)
async def get_exclusion(exclusion_id: str):
    """Obtiene una exclusión específica"""
    exclusion = exclusion_manager.get_exclusion(exclusion_id)
    if not exclusion:
        raise HTTPException(status_code=404, detail="Exclusion not found")
    return exclusion

@app.post("/api/exclusions", response_model=ExclusionRule)
async def create_exclusion(exclusion_request: ExclusionCreateRequest):
    """Crea una nueva exclusión"""
    try:
        exclusion = exclusion_manager.create_exclusion(exclusion_request)
        log(f"Created exclusion {exclusion.id}: {exclusion.name}")
        return exclusion
    except Exception as e:
        log(f"Error creating exclusion: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error creating exclusion: {str(e)}")

@app.put("/api/exclusions/{exclusion_id}", response_model=ExclusionRule)
async def update_exclusion(exclusion_id: str, update_request: ExclusionUpdateRequest):
    """Actualiza una exclusión"""
    try:
        exclusion = exclusion_manager.update_exclusion(exclusion_id, update_request)
        if not exclusion:
            raise HTTPException(status_code=404, detail="Exclusion not found")

        log(f"Updated exclusion {exclusion_id}")
        return exclusion
    except HTTPException:
        raise
    except Exception as e:
        log(f"Error updating exclusion {exclusion_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error updating exclusion: {str(e)}")

@app.delete("/api/exclusions/{exclusion_id}")
async def delete_exclusion(exclusion_id: str):
    """Elimina una exclusión"""
    try:
        if not exclusion_manager.delete_exclusion(exclusion_id):
            raise HTTPException(status_code=404, detail="Exclusion not found")

        log(f"Deleted exclusion {exclusion_id}")
        return {"message": "Exclusion deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        log(f"Error deleting exclusion {exclusion_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error deleting exclusion: {str(e)}")

@app.post("/api/exclusions/{exclusion_id}/toggle")
async def toggle_exclusion(exclusion_id: str):
    """Habilita/deshabilita una exclusión"""
    try:
        exclusion = exclusion_manager.get_exclusion(exclusion_id)
        if not exclusion:
            raise HTTPException(status_code=404, detail="Exclusion not found")

        update_request = ExclusionUpdateRequest(enabled=not exclusion.enabled)
        updated_exclusion = exclusion_manager.update_exclusion(exclusion_id, update_request)

        action = "enabled" if updated_exclusion.enabled else "disabled"
        log(f"Exclusion {exclusion_id} {action}")

        return {
            "message": f"Exclusion {action} successfully",
            "exclusion": updated_exclusion
        }
    except HTTPException:
        raise
    except Exception as e:
        log(f"Error toggling exclusion {exclusion_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error toggling exclusion: {str(e)}")

# Endpoint para la página de gestión de exclusiones
@app.get("/exclusions", response_class=HTMLResponse)
async def exclusions_page(request: Request):
    """Página de gestión de exclusiones"""
    return templates.TemplateResponse("exclusions_management.html", {"request": request})
