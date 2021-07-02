import os
import requests

"""
A very simple pod/job to take the existing elasticsearch credentials and make a dedicated user just for 
Stoq. This will be a cluster superuser until I bother to define a proper set of ES permissions for the stoq
transformer.
"""


def make_stoq_user():
    username = os.environ.get("STOQ_USER", "stoq")
    password = os.environ.get("STOQ_PASS", None)
    elastic_user = os.environ.get("ELASTIC_USER", "elastic")
    elastic_pass = os.environ.get("ELASTIC_PASS", None)
    post_data = {"password": password,
                 "roles": "superuser"
                 }
    response = requests.post(f"https://malwaretl-cluster-es-http.es:9200/_security/user/{username}",
                             data=post_data,
                             auth=(elastic_user, elastic_pass))
    if response.status_code not in (200, 201):
        raise Exception(f"problem with user creation: {response.json()}")


if __name__ == "__main__":
    make_stoq_user()
