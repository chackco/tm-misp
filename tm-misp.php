<?php

# TM-MISP web UI script for display IOC from Apex central and DSM
#

if(isset($_GET['url']) && (preg_match("/^([a-f0-9]{64})$/", strtolower($_GET['url'])) || preg_match('/^[0-9a-f]{40}$/i', strtolower($_GET['url'])))){
	$vt_link="https://www.virustotal.com/ui/files/".$_GET['url'];
	$vt_result=file_get_contents($vt_link);

	if(preg_match("/Invalid file hash/",$vt_result)){
	print("NO VT");
	}else{
		$tmp=explode("last_analysis_stats",$vt_result);
		$tmp2=explode("last_modification_date",$tmp[1]);
		$line=explode("\n",$tmp2[0]);
		for($i=1;$i<count($line)-1;$i++){
			if(preg_match("/malicious/",$line[$i])){
			print ($line[$i]."");
			}
			if(preg_match("/suspicious/",$line[$i])){
			print ($line[$i]."");
			}
			if(preg_match("/undetected/",$line[$i])){
			print ($line[$i]."");
			}
		}
#	print($line);	
		
	}
	exit;
	
}elseif(isset($_GET['url'])
){
	print($_GET['url']);
	exit;
}







$return_all_apex = json_decode(file_get_contents("/var/www/MISP/PyMISP/examples/list_apex_so.txt"));
$return_all_ds = json_decode(file_get_contents("/var/www/MISP/PyMISP/examples/list_ds_so.txt"));

	print("<html><head><title>TM-MISP Integration Portal</title>
		<meta charset='UTF-8'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<link rel='stylesheet' type='text/css' href='main.css'>
	</head><body>
		<div class=limiter>
		<div class=container-table100><h1>IOC List from MISP</h1>
			<div class=wrap-table100>
				<div class=table100>
	<table><thead>
	<tr class=table100-head><th class=column1>#</th><th class=column2>SHA256</th><th class=column3>SHA-1</th><th class=column6>Virus total</th></tr></thead><tbody>
	<script type='text/javascript'>
function loadVT(url_1,myDiv)
{
var xmlhttp;
if (window.XMLHttpRequest)
  {// code for IE7+, Firefox, Chrome, Opera, Safari
  xmlhttp=new XMLHttpRequest();
  }
else
  {// code for IE6, IE5
  xmlhttp=new ActiveXObject('Microsoft.XMLHTTP');
  }
xmlhttp.onreadystatechange=function()
  {
  if (xmlhttp.readyState==4)
    {
    document.getElementById(myDiv).innerHTML=xmlhttp.responseText;
	
    }
  }
xmlhttp.open('GET','tm-misp.php?url='+url_1,true);
xmlhttp.send();
}
</script>


");

$t=0;
$x=0;
$a=Array();
	foreach ($return_all_apex as $apex_key => $apex_value){
		#print("$apex_key");
		if(count($apex_value)<2){
			break;
		}
		for ($i=0;$i<count($apex_value);$i++){
			#print_r($apex_value[$i]);
			#print("<hr>");
			
			foreach($apex_value[$i] as $afield_name => $afield_value){
				if($afield_name === "content"){
					$aname_print=$afield_value;
				}
				if($afield_name === "notes" && preg_match("/MISP/",$afield_value)){
					$t++;
					array_push($a,$aname_print);
					#print "<p>$t. $aname_print</p>";
				}
			}
		}	
	}
	




 


$return_all_rule=$return_all_ds;


	$k=0;
	foreach ($return_all_rule as $globalrule => $array_of_rule){
		for ($i=0;$i<count($array_of_rule);$i++){
			foreach($array_of_rule[$i] as $field_name => $field_value){
				if($field_name === "sha256"){
					$name_print=$field_value;
				}
				if($field_name === "description" && preg_match("/MISP/",$field_value)){
					$k++;
					$name_print2="";
					$tmp=explode("=",$field_value);
					if(count($tmp)>1){
						
						$name_print2 = $tmp[1];
						$a = array_diff($a, array($tmp[1]));
					}
					$vt_link=$name_print;

					print("<tr><td class=column1>$k.</td><td class=column2>$name_print</td><td class=column3>$name_print2</td><td class=column6 nowrap><div id=myDiv$k><script>loadVT('$vt_link','myDiv$k')</script></div></td></tr>");
				}
			}
		}	
	}
	



	
	
	
	for($w=0;$w<count($a);$w++){
		
		print("<tr><td class=column1>$k.</td><td class=column2></td><td class=column3>$a[$w]</td><td class=column6 nowrap><div id=myDiv".($k+$w)."><script>loadVT('$a[$w]','myDiv".($k+$w)."')</script></div></td></tr>");
	}

	print("<tr><td class=column1>&gt;&gt;&gt;</td><td class=column2>Deep Security IOC: $k</td><td class=column3>Apex Central IOC: $t</td><td class=column6>Total: ".($k+$t)."</td></tr>");
	print("");
	print("</body></html>");
	print("</tbody></table>		</div>
			</div>
		</div>
	</div>");





?>
