class BaseComponent:
    def __init__(self, name: str):
        self.name = name
        self.running = False
    
    def start(self):
        raise NotImplementedError
    
    def stop(self):
        self.running = False
