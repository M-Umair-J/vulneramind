import pytest
import backend.core.scanner.fast_scanner as fast_scanner

def test_check_if_user_is_root_or_admin_returns_bool():
    assert isinstance(fast_scanner.check_if_user_is_root_or_admin(), bool)

def test_parser_returns_list():
    # mock scan_result structure
    fake_scan_result = {
        'ports': [
            {
                'type': 'tcp_connect',
                'result': {
                    'nmap': {
                        'scaninfo': {
                            'tcp': {'method': 'connect', 'services': '22'}
                        }
                    },
                    'scan': {
                        '127.0.0.1': {
                            'tcp': {
                                22: {'state': 'open'}
                            }
                        }
                    }
                }
            }
        ],
        'target': '127.0.0.1'
    }
    open_ports = fast_scanner.extract_open_ports_and_protocols(fake_scan_result, '127.0.0.1')
    assert isinstance(open_ports, list)
    assert len(open_ports) == 1
    assert open_ports[0]['port'] == 22
    assert open_ports[0]['protocol'] == 'tcp'
