# models.py
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey
)
from sqlalchemy.orm import relationship
from datetime import datetime

# Import Base from separate base.py to avoid circular imports
from src.db.base import Base


class Server(Base):
    __tablename__ = "server"

    id = Column(Integer, primary_key=True)
    hostname = Column(String, nullable=False)
    ip_address = Column(String)
    server_type = Column(String, nullable=False)

    logs = relationship("LogEntry", back_populates="server")


class LogEntry(Base):
    __tablename__ = "log_entry"

    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, ForeignKey("server.id"))
    recv_time = Column(DateTime, default=datetime.utcnow)
    log_source = Column(String, nullable=False)
    content = Column(Text, nullable=False)

    server = relationship("Server", back_populates="logs")
    linux_details = relationship("LinuxLogDetails", uselist=False)
    nginx_details = relationship("NginxLogDetails", uselist=False)
    windows_details = relationship("WindowsLogDetails", uselist=False)


class LinuxLogDetails(Base):
    __tablename__ = "linux_log_details"

    log_entry_id = Column(Integer, ForeignKey("log_entry.id"), primary_key=True)

    timestamp = Column(DateTime)
    app_name = Column(String)
    pid = Column(Integer)
    raw_message = Column(Text)
    ssh_action = Column(String)
    ssh_user = Column(String)
    ssh_ip = Column(String)


class NginxLogDetails(Base):
    __tablename__ = "nginx_log_details"

    log_entry_id = Column(Integer, ForeignKey("log_entry.id"), primary_key=True)

    remote_addr = Column(String)
    remote_user = Column(String)
    time_local = Column(DateTime)
    request_method = Column(String)
    request_uri = Column(String)
    server_protocol = Column(String)
    status = Column(Integer)
    body_bytes_sent = Column(Integer)
    http_referer = Column(String)
    http_user_agent = Column(String)


class WindowsLogDetails(Base):
    __tablename__ = "windows_log_details"

    log_entry_id = Column(Integer, ForeignKey("log_entry.id"), primary_key=True)
    content = Column(Text, nullable=False)   # JSON string


class AlertRule(Base):
    __tablename__ = "alert_rule"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    log_source = Column(String)  # linux, windows, nginx or None for all
    severity = Column(String, nullable=False)  # low, medium, high, critical
    enabled = Column(Integer, default=1)  # 1 = enabled, 0 = disabled
    rule_content = Column(Text)  # YAML or JSON rule definition
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alert"

    id = Column(Integer, primary_key=True)
    log_entry_id = Column(Integer, ForeignKey("log_entry.id"))
    server_id = Column(Integer, ForeignKey("server.id"))
    rule_id = Column(Integer, ForeignKey("alert_rule.id"))
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text)
    alert_metadata = Column(Text)  # JSON string - renamed from 'metadata'
    triggered_at = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Integer, default=0)  # 0 = active, 1 = resolved
