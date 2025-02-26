import pytest
import base64

from application_client.client import Client,build_coin_info
from contextlib import contextmanager
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavIns, NavInsID, Navigator, NavigateWithScenario
from utils import check_signature_validity, run_apdu_and_nav_tasks_concurrently

# can sign a simple Sui transfer transaction
def test_sign_tx_sui_transfer(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/784'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)
    assert len(public_key) == 32

    transaction = bytes.fromhex('000000000002000840420f000000000000204f2370b2a4810ad6c8e1cfd92cc8c8818fef8f59e3a80cea17871f78d850ba4b0202000101000001010200000101006fb21feead027da4873295affd6c4f3618fe176fa2fbf3e7b5ef1d9463b31e210112a6d0c44edc630d2724b1f57fea4f93308b1d22164402c65778bd99379c4733070000000000000020f2fd3c87b227f1015182fe4348ed680d7ed32bcd3269704252c03e1d0b13d30d6fb21feead027da4873295affd6c4f3618fe176fa2fbf3e7b5ef1d9463b31e2101000000000000000c0400000000000000')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        if firmware.device.startswith("nano"):
            navigator.navigate_and_compare(
                instructions=[ NavInsID.RIGHT_CLICK # Transfer SUI
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # From ...
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # To ...
                               , NavInsID.RIGHT_CLICK # Amount
                               , NavInsID.RIGHT_CLICK # Max Gas
                               , NavInsID.RIGHT_CLICK # Sign Transaction?
                               , NavInsID.BOTH_CLICK
                              ]
                , timeout=10
                , test_case_name="test_sign_tx_sui_transfer"
                , path=scenario_navigator.screenshot_path
                , screen_change_before_first_instruction=True
                , screen_change_after_last_instruction=False
            )
        else:
            scenario_navigator.review_approve()

    def check_result(result):
        assert len(result) == 64
        assert check_signature_validity(public_key, result, transaction)

    run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)


TX_DATA = [
    {
        'case_name': 'tx_simple',
        'tx_data': '01020300000301009fec961434e391d7106a2353f04be26052ba40254115004118e1be09b9724e2e615300000000000020eab1422236814f7dbbd2c3400dd46a11b412ef35fb62ba528c70fe76ec1310ad0008c7c7c7c700000000002087aa2830134adc42ed726fde1755e2af38469920314f936755de616c3b4b46fd02020100000101010001010200000102005a64eec558ee719741578942714a0b35058ced15d79f4af64da014715ada449701000000000000000000000000000000000000000000000000000000000000feee0a1a0000000000002000000000000000000000000000000000000000000000000000000000000000005a64eec558ee719741578942714a0b35058ced15d79f4af64da014715ada44970100000000000000424200000000000000',
        'obj_ids': ['9fec961434e391d7106a2353f04be26052ba40254115004118e1be09b9724e2e']
    },
    {
        'case_name': 'tx_with_merge',
        'tx_data': '010203000004010005d49733c40729a9deb191907c6121dbf86a972ee663de6928960aa16d98e5ba49195e1d000000002019a74f853f85db6b59f18ff417a9d34c98950abcacda3023202a18581b12784f01001aeaee00201e85eea634b143cc6f14d6ed294bf96d2e28639c2a8f87974be6a249195e1d00000000200270a4416dc6da420012c24501db485d1401b165478c7acf9820270b838fa6e4000804000000000000000020fd080526a3f6de7577e63b71d3f4cb93d83f3456e039a60ebb6f63dc377231b60303010000010101000201000001010200010103010000000103005390224bd7dd3e6d6573a45d4e6bcd2308b06bf13c0a268194a731ce237c94ba01c860d93d420af300076594a06ae9d5f53174999f7851af971ed4729f105fcb9949195e1d0000000020934767305ed431f2beb78c661f5f851909fb7ea9ee82a10a8c0f19791b8093205390224bd7dd3e6d6573a45d4e6bcd2308b06bf13c0a268194a731ce237c94baee02000000000000105e26000000000000',
        'obj_ids': [
            '05d49733c40729a9deb191907c6121dbf86a972ee663de6928960aa16d98e5ba',
            '1aeaee00201e85eea634b143cc6f14d6ed294bf96d2e28639c2a8f87974be6a2'
        ]
    }
]

# It tests token transfer transaction
@pytest.mark.parametrize('tx_data', TX_DATA, ids=lambda case: case['case_name'])
def test_sign_tx_token_transfer(backend, scenario_navigator: NavigateWithScenario, tx_data, firmware, navigator: Navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/784'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)
    assert len(public_key) == 32

    test_case_name = "test_sign_tx_token_transfer_" + tx_data['case_name']
    transaction = bytes.fromhex(tx_data['tx_data'])
    addresses = [bytes.fromhex(obj_id) for obj_id in tx_data['obj_ids']]

    def apdu_task():
        coin_info = build_coin_info(
            ticker=b"USDC",
            decimals=6,
            addresses=addresses,
        )
        client.set_coin_info(coin_info)

        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        if firmware.device.startswith("nano"):
            navigator.navigate_and_compare(
                instructions=[ NavInsID.RIGHT_CLICK # Transfer SUI
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # From ...
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # To ...
                               , NavInsID.RIGHT_CLICK # Amount
                               , NavInsID.RIGHT_CLICK # Max Gas
                               , NavInsID.RIGHT_CLICK # Sign Transaction?
                               , NavInsID.BOTH_CLICK
                              ]
                , timeout=10
                , test_case_name=test_case_name
                , path=scenario_navigator.screenshot_path
                , screen_change_before_first_instruction=True
                , screen_change_after_last_instruction=False
            )
        else:
            scenario_navigator.review_approve(
                path=scenario_navigator.screenshot_path
                , test_name=test_case_name
                , custom_screen_text=None,
            )

    def check_result(result):
        assert len(result) == 64
        assert check_signature_validity(public_key, result, transaction)

    run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

# can blind sign an unknown transaction
def test_sign_tx_blind_sign(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/784'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)

    transaction = bytes.fromhex('00000000050205546e7f126d2f40331a543b9608439b582fd0d103000000000000002080fdabcc90498e7eb8413b140c4334871eeafa5a86203fd9cfdb032f604f49e1284af431cf032b5d85324135bf9a3073e920d7f5020000000000000020a06f410c175e828c24cee84cb3bd95cff25c33fbbdcb62c6596e8e423784ffe702d08074075c7097f361e8b443e2075a852a2292e8a08074075c7097f361e8b443e2075a852a2292e80180969800000000001643fb2578ff7191c643079a62c1cca8ec2752bc05546e7f126d2f40331a543b9608439b582fd0d103000000000000002080fdabcc90498e7eb8413b140c4334871eeafa5a86203fd9cfdb032f604f49e101000000000000002c01000000000000')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        if firmware.device.startswith("nano"):
            navigator.navigate_and_compare(
                instructions=[ NavInsID.RIGHT_CLICK # Warning...
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # Transaction Hash
                               , NavInsID.RIGHT_CLICK # Blind Sign Transaction?
                               , NavInsID.BOTH_CLICK]
                , timeout=10
                , path=scenario_navigator.screenshot_path
                , test_case_name="test_sign_tx_blind_sign"
                , screen_change_before_first_instruction=False
                , screen_change_after_last_instruction=False
            )
        else:
            # Dismiss the "Blind signing ahead" screen
            navigator.navigate_and_compare(
                instructions=[NavInsID.USE_CASE_CHOICE_REJECT]
                , timeout=20
                , path=scenario_navigator.screenshot_path
                , test_case_name="test_sign_tx_blind_sign_1"
                , screen_change_before_first_instruction=True
                , screen_change_after_last_instruction=True
            )
            # Below is similar to scenario_navigator.review_approve()
            # But screen_change_before_first_instruction=True causes hang
            navigator.navigate_until_text_and_compare(
                navigate_instruction=NavInsID.SWIPE_CENTER_TO_LEFT
                , validation_instructions=[NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
                , text="^Hold to sign$"
                , timeout=20
                , path=scenario_navigator.screenshot_path
                , test_case_name="test_sign_tx_blind_sign_2"
                , screen_change_before_first_instruction=False
                , screen_change_after_last_instruction=True
            )

    def check_result(result):
        assert len(result) == 64
        assert check_signature_validity(public_key, result, transaction)

    with blind_sign_enabled(firmware, navigator):
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/784'/0'"

    transaction = bytes.fromhex('000000000002000840420f000000000000204f2370b2a4810ad6c8e1cfd92cc8c8818fef8f59e3a80cea17871f78d850ba4b0202000101000001010200000101006fb21feead027da4873295affd6c4f3618fe176fa2fbf3e7b5ef1d9463b31e210112a6d0c44edc630d2724b1f57fea4f93308b1d22164402c65778bd99379c4733070000000000000020f2fd3c87b227f1015182fe4348ed680d7ed32bcd3269704252c03e1d0b13d30d6fb21feead027da4873295affd6c4f3618fe176fa2fbf3e7b5ef1d9463b31e2101000000000000000c0400000000000000')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        if firmware.device.startswith("nano"):
            navigator.navigate_and_compare(
                instructions=[ NavInsID.RIGHT_CLICK # Transfer SUI
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # From ...
                               , NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK # To ...
                               , NavInsID.RIGHT_CLICK # Amount
                               , NavInsID.RIGHT_CLICK # Max Gas
                               , NavInsID.RIGHT_CLICK # Sign Transaction?
                               , NavInsID.RIGHT_CLICK # Confirm
                               , NavInsID.BOTH_CLICK
                              ]
                , timeout=10
                , test_case_name="test_sign_tx_refused"
                , path=scenario_navigator.screenshot_path
                , screen_change_before_first_instruction=True
                , screen_change_after_last_instruction=False
            )
        else:
            scenario_navigator.review_reject()

    def check_result(result):
        pytest.fail('should not happen')

    with pytest.raises(ExceptionRAPDU) as e:
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

    assert len(e.value.data) == 0

# should reject signing a non-SUI coin transaction, if blind signing is not enabled
def test_sign_tx_non_sui_transfer_rejected(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/784'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)
    assert len(public_key) == 32

    transaction = base64.b64decode('AAAAAAADAQAe2uv1Mds+xCVK5Jv/Dv5cgEl/9DthDcpbjWcsmFpzbs6BNQAAAAAAIKPD8GQqgBpJZRV+nFDRE7rqR0Za8x0pyfLusVdpPPVRAAgADl+jHAAAAAAg5y3MHATlk+Ik5cPIdEz5iPANs1jcXZHVGjh4Mb16lwkCAgEAAAEBAQABAQIAAAECAF/sd27xyQe/W+gY4WRtPlQro1siWQu79s0pxbbCSRafAfnjaU5yJSFFDJznsAaBqbkiR9CB8DJqWki8fn8AUZeQz4E1AAAAAAAgTRU/MsawTJirpVwjDF8gyiEbaT0+7J0V8ifUEGGBkcVf7Hdu8ckHv1voGOFkbT5UK6NbIlkLu/bNKcW2wkkWn+gDAAAAAAAA8NdGAAAAAAAA')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        if firmware.device.startswith("nano"):
            navigator.navigate_and_compare(
                instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK]
                , timeout=10
                , test_case_name="test_sign_tx_non_sui_transfer_rejected"
                , path=scenario_navigator.screenshot_path
                , screen_change_before_first_instruction=True
                , screen_change_after_last_instruction=False
            )
        else:
            # Dismiss the "Enable Blind signing" screen
            navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT],
                            screen_change_before_first_instruction=False,
                            screen_change_after_last_instruction=False)

    def check_result(result):
        pytest.fail('should not happen')

    with pytest.raises(ExceptionRAPDU) as e:
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

    assert len(e.value.data) == 0

# should reject signing an unknown transaction, if blind signing is not enabled
def test_sign_tx_unknown_tx_rejected(backend, scenario_navigator, firmware, navigator):
    client = Client(backend, use_block_protocol=True)
    path = "m/44'/784'/0'"

    _, public_key, _, _ = client.get_public_key(path=path)
    assert len(public_key) == 32

    transaction = bytes.fromhex('00000000050205546e7f126d2f40331a543b9608439b582fd0d103000000000000002080fdabcc90498e7eb8413b140c4334871eeafa5a86203fd9cfdb032f604f49e1284af431cf032b5d85324135bf9a3073e920d7f5020000000000000020a06f410c175e828c24cee84cb3bd95cff25c33fbbdcb62c6596e8e423784ffe702d08074075c7097f361e8b443e2075a852a2292e8a08074075c7097f361e8b443e2075a852a2292e80180969800000000001643fb2578ff7191c643079a62c1cca8ec2752bc05546e7f126d2f40331a543b9608439b582fd0d103000000000000002080fdabcc90498e7eb8413b140c4334871eeafa5a86203fd9cfdb032f604f49e101000000000000002c01000000000000')

    def apdu_task():
        return client.sign_tx(path=path, transaction=transaction)

    def nav_task():
        if firmware.device.startswith("nano"):
            navigator.navigate_and_compare(
                instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK]
                , timeout=10
                , test_case_name="test_sign_tx_unknown_tx_rejected"
                , path=scenario_navigator.screenshot_path
                , screen_change_before_first_instruction=True
                , screen_change_after_last_instruction=False
            )
        else:
            # Dismiss the "Enable Blind signing" screen
            navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT],
                            screen_change_before_first_instruction=False,
                            screen_change_after_last_instruction=False)

    def check_result(result):
        pytest.fail('should not happen')

    with pytest.raises(ExceptionRAPDU) as e:
        run_apdu_and_nav_tasks_concurrently(apdu_task, nav_task, check_result)

    assert len(e.value.data) == 0

@contextmanager
def blind_sign_enabled(firmware, navigator):
    toggle_blind_sign(firmware, navigator)
    try:
        yield
    except:
        # Don't re-enable if we hit an exception
        raise
    else:
        toggle_blind_sign(firmware, navigator)

def toggle_blind_sign(firmware, navigator):
    if firmware.device.startswith("nano"):
        navigator.navigate(
            instructions=[NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.LEFT_CLICK, NavInsID.LEFT_CLICK]
            , timeout=10
            , screen_change_before_first_instruction=False
        )
    else:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS,
                            NavIns(NavInsID.TOUCH, (200, 113)),
                            NavInsID.USE_CASE_SUB_SETTINGS_EXIT],
                            timeout=10,
                            screen_change_before_first_instruction=False,
                            screen_change_after_last_instruction=False)
