from ece404_hw04_ssabpisa import *

class UnitTest:
    @staticmethod
    def test_round_constants(KeyScheduleObj):
        assert(len(KeyScheduleObj.Rcon) == 10)

    @staticmethod
    def test_round_keys(KeyScheduleObj):
        xkey = KeyScheduleObj.xkey
        keyList = []
        for i,item in enumerate(xkey):
            keyList.append(item.getHexStringFromBitVector())

        print "---------- 44 Words -------------"
        print keyList
        assert(len(xkey) == 44)
        assert(xkey[40] + xkey[41] + xkey[42] + xkey[43] == KeyScheduleObj.get_key_for_round(10))
        for key in xkey:
            assert(len(key) == WORD)

    @staticmethod
    def test_shiftrow():
        M = [[None for r in range(4)] for c in range(4)]
        for i in range(4):
            for j in range(4):
                M[j][i] = BitVector(intVal=j,size=BYTE/2)+ BitVector(intVal=i, size=BYTE/2)

        Ms = AES.shiftrows(M)

        assert(Ms[0][0] == M[0][0])
        assert(Ms[0][1] == M[0][1])
        assert(Ms[0][2] == M[0][2])
        assert(Ms[0][3] == M[0][3])

        assert(Ms[1][0] == M[1][1])
        assert(Ms[1][1] == M[1][2])
        assert(Ms[1][2] == M[1][3])
        assert(Ms[1][3] == M[1][0])

        assert(Ms[2][0] == M[2][2])
        assert(Ms[2][1] == M[2][3])
        assert(Ms[2][2] == M[2][0])
        assert(Ms[2][3] == M[2][1])

        assert(Ms[3][0] == M[3][3])
        assert(Ms[3][1] == M[3][0])
        assert(Ms[3][2] == M[3][1])
        assert(Ms[3][3] == M[3][2])

    @staticmethod
    def test_esbox(LTB):
        assert(LTB[0][0].intValue() == 99)
        assert(LTB[0][1].intValue() == 124)
        assert(LTB[0][2].intValue() == 119)
        assert(LTB[15][15].intValue() == 22)