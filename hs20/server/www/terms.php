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

   $fp = fsockopen($hostapd_ctrl);
   if (!$fp) {
      die("Could not connect to hostapd(AS)");
   }

   fwrite($fp, "DAC_REQUEST coa $addr t_c_clear");
   fclose($fp);

   $waiting = true;
   $ack = false;
   for ($i = 1; $i <= 10; $i++) {
      $res = $db->prepare("SELECT waiting_coa_ack,coa_ack_received FROM current_sessions WHERE mac_addr=?");
      $res->execute(array($addr));
      $row = $res->fetch();
      if (!$row) {
         die("No current session for the specified MAC address");
      }
      $waiting = $row[0] == 1;
      $ack = $row[1] == 1;
      $res->closeCursor();
      if (!$waiting)
         break;
      sleep(1);
   }
   if ($ack) {
      echo "<P>Filtering disabled.</P>\n";
   } else {
      echo "<P>Failed to disable filtering.</P>\n";
   }
}

?>

</body>
</html>
