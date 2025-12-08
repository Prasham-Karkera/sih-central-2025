import os
import sys
import time
import threading
import importlib.util
import logging
from pathlib import Path

# Setup logging
logger = logging.getLogger("PluginManager")

class PluginManager:
    def __init__(self, app=None, socketio=None, log_store=None):
        self.app = app
        self.socketio = socketio
        self.log_store = log_store
        self.plugins = []
        self.loaded_files = set()

        # Determine where the .exe is running to find the 'plugins' folder
        if getattr(sys, 'frozen', False):
            self.base_path = Path(sys.executable).parent
        else:
            self.base_path = Path(__file__).parent

        self.plugin_folder = self.base_path / "plugins"
        
        # Start the watcher thread
        self.running = True
        self.watcher_thread = threading.Thread(target=self._watch_folder, daemon=True)
        self.watcher_thread.start()

    def _watch_folder(self):
        """Background loop to check for new files"""
        if not self.plugin_folder.exists():
            self.plugin_folder.mkdir(exist_ok=True)

        while self.running:
            try:
                current_files = set()
                for file_path in self.plugin_folder.glob("*.py"):
                    if file_path.name == "__init__.py":
                        continue
                    
                    current_files.add(file_path)
                    
                    # Check if this is a NEW file we haven't seen
                    if file_path not in self.loaded_files:
                        print(f"[PLUGIN WATCHER] New plugin file found: {file_path.name}")
                        logger.info(f"New plugin found: {file_path.name}")
                        
                        # Attempt to load it immediately
                        try:
                            self._load_single_plugin(file_path)
                            self.loaded_files.add(file_path)
                            print(f"[PLUGIN WATCHER] Successfully loaded: {file_path.name}")
                        except Exception as e:
                            print(f"[PLUGIN ERROR] Failed to load {file_path.name}: {e}")

                # Optional: Handle deleted files (remove from loaded_files)
                # For now, we just track additions.
                
            except Exception as e:
                print(f"[PLUGIN WATCHER ERROR] {e}")
            
            time.sleep(3)  # Check every 3 seconds

    def load_plugins(self):
        """Initial scan called on startup"""
        if not self.plugin_folder.exists():
            logger.info(f"Creating plugins directory at {self.plugin_folder}")
            self.plugin_folder.mkdir(exist_ok=True)
            return

        logger.info(f"Scanning for plugins in {self.plugin_folder}...")

        for file_path in self.plugin_folder.glob("*.py"):
            if file_path.name == "__init__.py":
                continue
            
            try:
                self._load_single_plugin(file_path)
                self.loaded_files.add(file_path) # Mark as loaded
            except Exception as e:
                logger.error(f"Failed to load plugin {file_path.name}: {e}")

    def load_plugin(self, path):
        """Manually load a specific plugin file."""
        path = Path(path)
        if path in self.loaded_files:
            logger.info(f"Plugin {path.name} already loaded.")
            return

        try:
            self._load_single_plugin(path)
            self.loaded_files.add(path)
            logger.info(f"Manually loaded plugin: {path.name}")
        except Exception as e:
            logger.error(f"Failed to manually load plugin {path.name}: {e}")
            raise e

    def _load_single_plugin(self, path):
        # 1. Load the module dynamically
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # 2. Look for a 'SentinelExtension' class in the module
        if hasattr(module, "SentinelExtension"):
            plugin_class = getattr(module, "SentinelExtension")
            plugin_instance = plugin_class()
            
            # 3. Register the plugin
            self.plugins.append(plugin_instance)
            
            # 4. Initialize the plugin (Pass Core Systems)
            if hasattr(plugin_instance, "on_load"):
                plugin_instance.on_load(self.app, self.socketio, self.log_store)
                
            logger.info(f"Successfully loaded plugin: {plugin_instance.name}")
            
            # 5. Notify Frontend
            if self.socketio:
                self.socketio.emit('backend_plugin_added', {'name': plugin_instance.name, 'file': path.name})

            # --- NEW: Send UI Component to Frontend ---
            if hasattr(plugin_instance, "get_gui_component"):
                html_content = plugin_instance.get_gui_component()
                if html_content and self.socketio:
                    print(f"[PLUGIN MANAGER] Sending UI for {plugin_instance.name}")
                    self.socketio.emit('plugin_added', {
                        'name': path.name,  # Use filename as ID
                        'content': html_content
                    })
            # ------------------------------------------

    def run_log_hooks(self, log_data):
        """Passes log data through all plugins for modification/enrichment."""
        for plugin in self.plugins:
            if hasattr(plugin, "process_log"):
                try:
                    result = plugin.process_log(log_data)
                    if result:
                        log_data = result
                except Exception as e:
                    logger.error(f"Error in plugin {plugin.name} process_log: {e}")
        return log_data