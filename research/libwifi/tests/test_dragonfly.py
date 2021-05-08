from libwifi import *

def test_crypto():
	x = 32774075109236952337158599048510140249162039589740847669274255820096074575478
	y = 65816200486131266053931191249788950977703402544735864608496951271815280382692
	assert point_on_curve(x, y)
	assert not point_on_curve(x, y + 1)


def test_sae():
	# KDF_Length with 256 bits
	data = b'p(b\x08\x84%\xd4\xfc\x85\x02`>Z\x8e8\x02\x06\xdcak1_\x8a\xca\x90D2[\xda\x88\x87\xbe'
	label = "SAE Hunting and Pecking"
	context = b'\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
	result = KDF_Length(data, label, context, 256)
	assert result == b"\xce\xd7\x0c`n\xc3\xa0V\xbc\xe5<Y\xd3\x80f@'.\xa3\xd8\x18\xedr\xd4/\xc8\x8a)\x18?G\xc4"

	# TODO: Test KDF_Length and derive_pwe_ecc with 521 bits

	# Needs one iteration
	pwe = derive_pwe_ecc("password", "01:02:03:04:05:06", "11:22:33:44:55:66")
	assert pwe.x == 93556404347856098254252288489266236507096062950733110787978910790160278833092
	assert pwe.y == 78525808305378972147720640984042921538517312040012375950098621853813571375494

	# Needs 4 iterations
	pwe = derive_pwe_ecc("OtherPassword4", "01:02:03:04:05:06", "11:22:33:44:55:66")
	assert pwe.x == 64608214587651293351943984050978725016684752726028646409621871614902214025509
	assert pwe.y == 6010654006319004793785415601018381818802850726803703928480923751376254632130


def test_eappwd():
	data = b'yKY2\xdfVP_\x84R\x04d\t\xa9\xac\xc0\xd0\x81\xe7\x01\xaa5\xe0\xd5r\xb6K\xb1g\xe0\xc8\xca'
	label = "EAP-pwd Hunting And Pecking"
	result = KDF_Length_eappwd(data, label, 256)
	assert result == b'\x82\xe7\x92\xd75\xfc\xef\x0e:\xb1\xea\x85E\xe6\rt\x849\xd6\xc3l\xcd\x00\x8e\xde\x94\xe4\xde\xa6q\x91\x1e'

	data = b'\xa8\xd5\x0c\xf47\x9b\xd0\x1d\x89\x1d\x1f\xf4\xa1\xeb\xdd\x9e\x17\x9d\xecm\xd8\xe6A2\x9c\xde$p\x9a\xcb\xd5N'
	result = KDF_Length_eappwd(data, label, 256)
	assert result == b'\xc8r\xfdke\xce\xfa\xbb\x0e\xc3\xb8\x83\xc2\x04\x95\x9fT\xc3P\xa9\x1be\x84\x16\xfba&\xc0!\xfbMs'

	data = binascii.unhexlify("8726279f4137e57cc040cc23bdf7053217dc613bae7defe2549c5bb75ad72a79")
	expect = binascii.unhexlify("ab8c540cf06cb38138670bb4e64b93d1f1232ae94f27bc19106bc84be6d0297bc2bf4b30418e12eed79462304bf12563a6b211984acf4c95005875f5b94d19c06400")
	result = KDF_Length_eappwd(data, label, 521)
	assert result == expect

	data = binascii.unhexlify("2683a19c41fd2ad1736f3efdccfee34afcd9866ee4e213b8e23d191f4ce5a4f7")
	expect = binascii.unhexlify("60d5d03a90e5ee8d08e1390f50b070330b4680dc8cf974e3227a8c09eedc56d975b191c7ea3ef5d0adcc0fa777bedcea9910098d3b02d1741699bfe8fa39be69a880")
	result = KDF_Length_eappwd(data, label, 521)
	assert result == expect

	data = b'\x82\x02\x07\xceX\xf5\xbb\x11s\xdc\xe4\xcb\xcc"\xa9\x1f\'\x19\xe0\xee\x84w\xb7\xd6G\xad\xa6w_\xf1\x8eg'
	label = b'4%\xfe\x8e\xd4\x93YD\xb3\xe7\xea\x8coN\xac\xf1 r\x83\x86u\xe1I\xbeS\xa7\x12l\xea\xbdhw\xc7'
	result = KDF_Length_eappwd(data, label, 1024)
	expected  = b's\xdd\xb9\xcf]\x80\x08\xf6\xa08\xf1J L\x8d\xd5\xa9j\x83J\x9d\x04T(\x1a\xbc\x11o\xab\x015\x82V\xd8\xff>J'
	expected += b'\x80P\x1f[PB\xfaF\x13\xae\xef\xfd\xddBkX\xff\xe03\xd3q(\x80\x9f"S\xad\xfeK:\x98\x90\xde\xdfw'
	expected += b'\xd5\xe4\xf0O\xcf\x9c\xa1\r^\xf3\xf6\x1fp_\xd9\x13<\xf7\x0e\xf11\x81\x88\xb9\xfe\x80mn\xed\xf2'
	expected += b'\xdel\x8f8f\\\xd4\x91\x83}|\xd0\x90\xa6I\xac\xca\xdb\x1d4\x00\xf5\xf8\xf5/\xa1'
	assert result == expected

	k = 34571911558658786479991772754682275693090212979118519100150784653967632958583
	e1x = 35056562182093533434520846036041768262744712948121085631797144112066231820275
	e1y = 30178867311470377631935198005507521070028138958470370567962433403317268006022
	e1 = ECC.EccPoint(e1x, e1y)
	s1 = 25673957538626389018921350300691255233489834439459044820849488820063961042178
	e2x = 55846548926525467025361797152934092596912359473099878093027981331310692689958
	e2y = 25540727936496301520339336932631497861346599764823572263118430938562903665071
	e2 = ECC.EccPoint(e2x, e2y)
	s2 = 89671311642711662572527453485728796207545960881415665173397225314404138450610
	confirm = calculate_confirm_eappwd(k, e1, s1, e2, s2)
	assert confirm == b"n\xe1N\xc1\x86\x0f\x94\x85W*Y\xf8\xf2'\x19\xac\x9c\xf6\xe6\xe6\x14\x8c+\xf7\x0e\xd0\xfdF\x87\x03G\xcc"

	pwe = derive_pwe_ecc_eappwd("password", "user", "server", 2903600207)
	assert pwe.x == 65324672961960968584356420288746215288928369435013474055323481826901726558522
	assert pwe.y == 81287605691219879983190651062276165371083848816381214499332721121120114417256

	pwe = derive_pwe_ecc_eappwd("password", "user", "server", 2546484939)
	assert pwe.x == 32774075109236952337158599048510140249162039589740847669274255820096074575478
	assert pwe.y == 65816200486131266053931191249788950977703402544735864608496951271815280382692

	pwe = derive_pwe_ecc_eappwd("hello", "bob", "theserver@example.com", 0xEE04524, curve_name="p521")
	assert pwe.x == 3008622341264366589487649162226557348235630833654679745848438214237061388319208914517686003128943873854271397962689455307621303688693893126759626682265352869
	assert pwe.y == 649775647643090676911381912723346979966421674682002310678312738784243727860456911539411456724737204490685667258758093054491548052506429972664016924839683943

