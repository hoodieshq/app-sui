import pytest

from application_client.client import Client, Errors
from contextlib import contextmanager
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns
from utils import ROOT_SCREENSHOT_PATH, run_apdu_and_nav_tasks_concurrently


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend):
    for path in [ "m/44'/535348'/0'"]:
        client = Client(backend)
        _, public_key, _, _ = client.get_public_key(path=path)

        assert public_key.hex() == "19e2fea57e82293b4fee8120d934f0c5a4907198f8df29e9a153cfd7d9383488"


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm_accepted(backend, scenario_navigator, firmware, navigator):
    client = Client(backend)
    path = "m/44'/535348'/0'"

    def nav_task():
        scenario_navigator.address_review_approve()

    def apdu_task():
        return client.get_public_key_with_confirmation(path=path)

    def check_result(result):
        _, public_key, _, _ = result
        assert public_key.hex() == "19e2fea57e82293b4fee8120d934f0c5a4907198f8df29e9a153cfd7d9383488"

    run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

# # In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
# def test_get_public_key_confirm_refused(backend, scenario_navigator):
#     client = Client(backend)
#     path = "m/44'/535348'/0'"

#     with pytest.raises(ExceptionRAPDU) as e:
#         with client.get_public_key_with_confirmation(path=path):
#             scenario_navigator.address_review_reject()

#     # Assert that we have received a refusal
#     assert e.value.status == Errors.SW_DENY
#     assert len(e.value.data) == 0

