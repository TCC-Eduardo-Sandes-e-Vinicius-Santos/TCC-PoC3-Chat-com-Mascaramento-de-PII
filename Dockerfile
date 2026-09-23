FROM apache/kafka:3.9.2

EXPOSE 9092 9093

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=10 \
    CMD /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 || exit 1