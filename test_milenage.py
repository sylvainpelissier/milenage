from unittest import TestCase
from milenage  import ReadMilenageInput, GenerateAuthTriplets


def test_milenage():
    attribs = ReadMilenageInput("input")
    #Generate auth triplets now
    for keyset in attribs:
        GenerateAuthTriplets(keyset)
    
    # Test Set 19 from 3GPP TS 55.205
    assert attribs[0]["sres"] == b'df58522f'
    assert attribs[0]["kc"] == b'ed29b2f1c27f9f34'
    assert attribs[0]["opc"] == b'cb9cccc4b9258e6dca4760379fb82581'

    # Test Set 18 from 3GPP TS 55.205
    assert attribs[1]["sres"] == b'8a3b8d17'
    assert attribs[1]["kc"] == b'9a8d0e883ff0887a'
    assert attribs[1]["opc"] == b'981d464c7c52eb6e5036234984ad0bcf'

    # Test Set 17 from 3GPP TS 55.205
    assert attribs[2]["sres"] == b'67e4ff3f'
    assert attribs[2]["kc"] == b'a819e577a8d6175b'
    assert attribs[2]["opc"] == b'df0c67868fa25f748b7044c6e7c245b8'