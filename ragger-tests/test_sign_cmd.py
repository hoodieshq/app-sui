import pytest
import concurrent.futures
import time

from application_client.client import Client, Errors
from contextlib import contextmanager
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavIns, NavInsID
from utils import ROOT_SCREENSHOT_PATH, check_signature_validity, run_apdu_and_nav_tasks_concurrently

def test_sign_tx_short_tx(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/535348'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)
    assert len(public_key) == 32

    transaction="smalltx".encode('utf-8')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        navigator.navigate_and_compare(
            instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
            , timeout=10
            , path=scenario_navigator.screenshot_path
            , test_case_name="test_sign_tx_short_tx"
            , screen_change_before_first_instruction=False
            , screen_change_after_last_instruction=False
        )

    def check_result(result):
        assert len(result) == 64
        assert check_signature_validity(public_key, result, transaction)

    with blind_sign_enabled(navigator):
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

def test_sign_tx_long_tx(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/535348'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)

    transaction=("looongtx" * 100).encode('utf-8')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        navigator.navigate_and_compare(
            instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
            , timeout=10
            , path=scenario_navigator.screenshot_path
            , test_case_name="test_sign_tx_long_tx"
            , screen_change_before_first_instruction=False
            , screen_change_after_last_instruction=False
        )

    def check_result(result):
        assert len(result) == 64
        assert check_signature_validity(public_key, result, transaction)

    with blind_sign_enabled(navigator):
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/535348'/0'"

    transaction="smalltx".encode('utf-8')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        navigator.navigate_and_compare(
            instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
            , timeout=10
            , path=scenario_navigator.screenshot_path
            , test_case_name="test_sign_tx_refused"
            , screen_change_before_first_instruction=False
            , screen_change_after_last_instruction=False
        )

    def check_result(result):
        assert len(result) == 64
        assert check_signature_validity(public_key, result, transaction)

    with pytest.raises(ExceptionRAPDU) as e:
        with blind_sign_enabled(navigator):
            run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

    # Assert that we have received a refusal
    # assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0

def test_sign_tx_blindsign_disabled(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/535348'/0'"

    transaction="smalltx".encode('utf-8')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        navigator.navigate_and_compare(
            instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK]
            , timeout=10
            , path=scenario_navigator.screenshot_path
            , test_case_name="test_sign_tx_blindsign_disabled"
            , screen_change_before_first_instruction=False
            , screen_change_after_last_instruction=False
        )

    def check_result(result):
        assert len(result) == 64

    with pytest.raises(ExceptionRAPDU) as e:
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

    # Assert that we have received a refusal
    # assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0

@contextmanager
def blind_sign_enabled(navigator):
    toggle_blind_sign(navigator)
    try:
        yield
    finally:
        toggle_blind_sign(navigator)

def toggle_blind_sign(navigator):
    navigator.navigate(
        instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.LEFT_CLICK, NavInsID.LEFT_CLICK]
        , timeout=10
        , screen_change_before_first_instruction=False
    )
