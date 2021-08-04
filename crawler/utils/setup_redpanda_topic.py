# © Copyright 2021 HP Development Company, L.P.
from kafka.admin import KafkaAdminClient, NewTopic


def check_topic():
    admin_client = KafkaAdminClient(
        bootstrap_servers="redpanda-1:29092",
        client_id='test'
    )
    if "urls" not in admin_client.list_topics():
        topic_list = []
        topic_list.append(NewTopic(name="urls", num_partitions=10, replication_factor=1))
        admin_client.create_topics(new_topics=topic_list, validate_only=False)
