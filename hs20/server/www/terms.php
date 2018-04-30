<?php

require('config.php');

$db = new PDO($osu_db);
if (!$db) {
   die($sqliteerror);
}

if (!isset($_GET["addr"])) {
   die("Missing addr parameter");
}
$addr = $_GET["addr"];

$accept = isset($_GET["accept"]) && $_GET["accept"] == "yes";

$res = $db->prepare("SELECT identity FROM pending_tc WHERE mac_addr=?");
$res->execute(array($addr));
$row = $res->fetch();
if (!$row) {
   die("No pending session for the specified MAC address");
}
$identity = $row[0];
?>
<html>
<head><title>HS 2.0 Terms and Conditions</title></head>
<body>

<?php

if (!$accept) {
   echo "<p>Accept the following terms and conditions by clicking here: <a href=\"terms.php?addr=$addr&accept=yes\">Accept</a></p>\n<hr>\n";
   readfile($t_c_file);
} else {
   $res = $db->prepare("UPDATE users SET t_c_timestamp=? WHERE identity=?");
   if (!$res->execute(array($t_c_timestamp, $identity))) {
      echo "<p>Failed to update user account.</p>";
   } else {
      $res = $db->prepare("DELETE FROM pending_tc WHERE mac_addr=?");
      $res->execute(array($addr));

      echo "<p>Terms and conditions were accepted.</p>";
   }
}

?>

</body>
</html>
