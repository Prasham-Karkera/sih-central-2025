import sqlite3
import json
import time
import os
import pickle
import math
import datetime
from river import anomaly, compose, preprocessing, feature_extraction
from sklearn.feature_extraction import FeatureHasher
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

# --- CONFIGURATION ---
DB_PATH = "../ironclad_logs.db"
MODELS_DIR = "hive_models"
POLL_INTERVAL = 2

# ==========================================
# 1. UTILITY: MATH ENGINE
# ==========================================


def calculate_entropy(text):
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text)
            for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

# ==========================================
# 2. SPECIALIZED PARSERS
# ==========================================


class WindowsParser:
    # ... (Your WindowsParser implementation remains unchanged) ...
    def init(self):
        self.user_keys = ['SubjectUserName', 'Subject_Account_Name',
                          'User_Account_Name', 'user', 'TargetUserName']
        self.process_keys = [
            'ProcessName', 'ProcessInformation_Process_Name', 'CallerProcessName', 'NewProcessName']
        self.host_keys = ['hostname', 'Computer', 'ingest_src_ip']
        self.last_ts = {}

    def _get_val(self, log, keys):
        for k in keys:
            if k in log and log[k]:
                return str(log[k]).lower().strip()
        return "unknown"

    def parse(self, content):
        try:
            log = json.loads(content) if isinstance(content, str) else content
        except:
            return None

        host = self._get_val(log, self.host_keys)
        event_id = str(log.get('event_id', '0'))
        process = self._get_val(log, self.process_keys).split('\\')[-1].lower()
        user = self._get_val(log, self.user_keys).lower()

        # Delta
        current_ts = datetime.datetime.now().timestamp()
        if 'timestamp' in log:
            try:
                dt = datetime.datetime.strptime(
                    log['timestamp'], "%Y-%m-%d %H:%M:%S")
                current_ts = dt.timestamp()
            except:
                pass

        delta = 0.0
        if host in self.last_ts:
            delta = current_ts - self.last_ts[host]
        self.last_ts[host] = current_ts

        return {
            'id': event_id,
            'vars': [process, user],
            'delta': delta,
            'entropy': 0.0  # Placeholder
        }


class LinuxParser:
    def init(self):
        config = TemplateMinerConfig()
        config.load_ini_config = False
        config.profiling_enabled = False
        self.miner = TemplateMiner(None, config)
        self.last_ts = 0.0

    def parse(self, content):
        if not content:
            return None

        # 1. Drain3 Parsing
        result = self.miner.add_log_message(content)
        template_id = str(result['cluster_id'])
        vars_list = result['template_mined']
        if isinstance(vars_list, str):
            vars_list = [vars_list]

        # 2. Extract App Name (Heuristic: "sshd[123]:")
        app_name = "unknown"
        try:
            parts = content.split(':')
            if len(parts) > 2:
                meta = parts[2].strip()
                app_name = meta.split('[')[0]
        except:
            pass

        # 3. Entropy on Variables
        vars_str = " ".join(vars_list)
        entropy = calculate_entropy(vars_str)

        # 4. Delta
        now = datetime.datetime.now().timestamp()
        delta = now - self.last_ts if self.last_ts > 0 else 0.0
        self.last_ts = now

        return {
            'id': template_id,
            'vars': [app_name] + vars_list,  # Add app name to features
            'delta': delta,
            'entropy': entropy
        }

# ==========================================
# 3. AGENTS
# ==========================================


class WindowsAgent:
    def init(self):
        self.parser = WindowsParser()
        self.hasher = FeatureHasher(n_features=20, input_type='string')
        self.model = anomaly.HalfSpaceTrees(
            n_trees=50, height=10, window_size=250, seed=42)
        self.threshold = 0.70

    def process(self, content):
        parsed = self.parser.parse(content)
        if not parsed:
            return 0.0, False, None

        raw_cat = [parsed['id']] + parsed['vars']
        hashed = self.hasher.transform([raw_cat]).toarray()[0]

        x = {f'h{i}': v for i, v in enumerate(hashed)}
        x['delta'] = parsed['delta']

        score = self.model.score_one(x)
        if score < 0.85:
            self.model.learn_one(x)

        return score, score > self.threshold, parsed


class LinuxAgent:
    def init(self):
        self.parser = LinuxParser()
        self.hasher = FeatureHasher(
            n_features=40, input_type='string')  # More features for text
        self.model = anomaly.HalfSpaceTrees(
            n_trees=50, height=10, window_size=250, seed=42)
        self.threshold = 0.70

    def process(self, content):
        parsed = self.parser.parse(content)
        if not parsed:
            return 0.0, False, None

        raw_cat = [parsed['id']] + parsed['vars']
        hashed = self.hasher.transform([raw_cat]).toarray()[0]

        x = {f'h{i}': v for i, v in enumerate(hashed)}
        x['delta'] = parsed['delta']
        x['entropy'] = parsed['entropy']

        # Hard Heuristics
        is_burst = parsed['delta'] < 0.01
        is_high_ent = parsed['entropy'] > 5.5

        score = self.model.score_one(x)

        is_anomaly = False
        if is_burst or is_high_ent:
            score = 1.0
            is_anomaly = True
        elif score > self.threshold:
            is_anomaly = True

        if not is_anomaly:
            self.model.learn_one(x)

        return score, is_anomaly, parsed

# ==========================================
# 4. HIVE MANAGER
# ==========================================


class UnifiedHive:
    def _init_(self):
        self.brains = {}  # Make sure this line is present!
        if not os.path.exists(MODELS_DIR):
            os.makedirs(MODELS_DIR)
        self.load_state()

    def load_state(self):
        for f in os.listdir(MODELS_DIR):
            if f.endswith(".pkl"):
                host = f.replace(".pkl", "")
                try:
                    with open(os.path.join(MODELS_DIR, f), "rb") as file:
                        self.brains[host] = pickle.load(file)
                except:
                    pass

    def save_state(self):
        for host, agent in self.brains.items():
            try:
                with open(os.path.join(MODELS_DIR, f"{host}.pkl"), "wb") as f:
                    pickle.dump(agent, f)
            except:
                pass

    def ingest_from_db(self):
        print(f"[*] Connecting to Database: {DB_PATH}")
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        print("-" * 130)
        print(f"{'SCORE':<8} | {'STATUS':<10} | {'OS':<5} | {'HOST':<15} | {'DETAILS'}")
        print("-" * 130)

        last_id = 0
        try:
            while True:
                query = """
                SELECT le.id, le.recv_time, le.log_source, s.hostname,
                       w.content as win_data,
                       l.raw_message as lin_data
                FROM log_entry le
                JOIN server s ON le.server_id = s.id
                LEFT JOIN windows_log_details w ON le.id = w.log_entry_id
                LEFT JOIN linux_log_details l ON le.id = l.log_entry_id
                WHERE le.id > ? ORDER BY le.id ASC LIMIT 500
                """
                cursor.execute(query, (last_id,))
                rows = cursor.fetchall()

                if not rows:
                    time.sleep(POLL_INTERVAL)
                    continue

                for row in rows:
                    last_id = row['id']
                    host = row['hostname'].lower().strip()
                    source = row['log_source']
                    content = row['win_data'] if source == 'windows' else row['lin_data']

                    if not content:
                        continue

                    # Spawn
                    if host not in self.brains:
                        if source == 'windows':
                            self.brains[host] = WindowsAgent()
                        else:
                            self.brains[host] = LinuxAgent()

                    # Process
                    ts = datetime.datetime.now().timestamp()
                    score, is_anomaly, info = self.brains[host].process(
                        content)

                    if info is None:
                        continue

                    # Visualize
                    os_label = "WIN" if source == 'windows' else "LIN"

                    if is_anomaly:
                        print(f"\n\033[91m" + "="*100)
                        print(
                            f" >> [ANOMALY] Host: {host} ({os_label}) | Score: {score:.4f}")
                        print("="*100 + f"\033[0m")

                        if source == 'windows':
                            print(
                                f"\033[91m   Event: {info['id']} | Proc: {info['vars'][0]} | User: {info['vars'][1]}\033[0m")
                        else:
                            print(
                                f"\033[91m   App: {info['vars'][0]} | Template: {info['id']}\033[0m")
                            print(
                                f"\033[91m   Vars: {info['vars'][1:]} | Entropy: {info['entropy']:.2f}\033[0m")

                        print(f"\033[91mRAW: {content[:200]}...\033[0m")
                        print("-" * 100 + "\n")
                    else:
                        status = "\033[92mOK\033[0m"
                        if source == 'windows':
                            summary = f"{info['id']} - {info['vars'][0]} - {info['vars'][1]}"
                        else:
                            # Linux Summary: TID - AppName - Vars
                            v_str = str(info['vars'][1:])[:40]
                            summary = f"TID:{info['id']} | {info['vars'][0]} | {v_str}"

                        if len(summary) > 70:
                            summary = summary[:67] + "..."
                        print(
                            f"{score:.4f}   | {status:<10} | {os_label:<5} | {host:<15} | {summary}")

                self.save_state()

        except KeyboardInterrupt:
            self.save_state()
        finally:
            conn.close()


if __name__ == "__main__":
    hive = UnifiedHive()
    hive.ingest_from_db()