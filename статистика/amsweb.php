<?php
//-------- Пароль доступа к статистике ------
// В целях безопасности настроятельно рекомендуем задать пароль доступка в следующей строчке.
// Этот пароль нужно будет так же указать в AMS в разделе Настройки->RealTime статистика при
// добавлении ссылки на данный скрипт.

$Password="qwery";

//-------- Заголовок Html ------------------
header('Content-Type: text/html; charset=utf-8');
$HtmlHead='<html><head><META content="text/html; charset=utf-8" http-equiv=Content-Type><title>Обработка данных</title></head>';

//--------- Сообщения форм -----------------
// В следующих строках можно задать сообщения, которые будут показаны скриптом после отправки
// формы подписки/отписки и кликов на ссылки-подтверждения.

$Form_Submit_Error="Введен не корректный E-Mail адрес<br>Пожалуйста, введите правильный E-Mail для успешной отправки формы";
$Form_Submit_OK="Спасибо.<br>Ваш запрос обрабатывается.<br>Вы получите запрос на подтверждение подписки на указанный e-mail";
$Confirmation_Link_Click="Подтверждение получено, спасибо !";
$Unsubscribe_Link_Click="Спасибо, Вы были успешно отписаны от нашей рассылки !";
//------------------------------------------

$ProgID = "-1";
$MailingID = -1;
$GroupID = -1;
$MessageID = -1;
$RcptEmail = "no_email";
$Form_Email = "no_email";
$MakeCopy = 0;
$GetCopy = 0;
$RedirURL = "nourl";
$FormName = "no_form";
$UnsubcrubeClick = 0;
$Form_FullName = "no_form_fullname";
$UnsubscribeAction = "no_action";
$ContactID="-1";
$ClientIP=$_SERVER['REMOTE_ADDR'];

if(count($_GET)===0 && count($_POST)===0)
	{
	// check script installation and required modules
	CheckScriptInstallation();
	exit;
	}
if(isset($_GET["GetIPInfo"]))
	{
	echo $ClientIP."=".gethostbyaddr($_SERVER['REMOTE_ADDR']);
	exit;
	}
if(isset($_POST["FormID"]))
	{
	// check is subscribe/unsubscribe form submitted
        $FormName = trim($_POST["FormID"]);
	if(isset($_POST["FormProgID"]))
		$ProgID = trim($_POST["FormProgID"]);
	else
		{
		echo "Unknown ProgramID";
		exit;
		}	
	if(isset($_POST["FormEmail"]) && !empty($_POST["FormEmail"]))
		{
	        $Form_Email = trim(strtolower($_POST["FormEmail"]));
		if((preg_match("/(@.*@)|(\.\.)|(@\.)|(\.@)|(^\.)/",$Form_Email)) or (!preg_match("/^.+\@(\[?)[a-zA-Z0-9\-\.]+\.([a-zA-Z]{2,6}|[0-9]{1,3})(\]?)$/",$Form_Email)))
			{
			echo $HtmlHead."<body BGCOLOR=\"#E6E6E6\"><div align=\"center\"><FONT color=\"#003399\"$Form_Submit_Error</FONT></div></body></html>";
			exit;
 			}
		}
	else
		{
		echo $HtmlHead."<body BGCOLOR=\"#E6E6E6\"><div align=\"center\"><FONT color=\"#003399\"<br>$Form_Submit_Error</FONT></div></body></html>";
		exit;
		}
	if(isset($_POST["FormFullName"]) && !empty($_POST["FormFullName"]))
        	$Form_FullName = trim($_POST["FormFullName"]);
	}
else
	{
	// Traceable link click/opened message counter/(un)subscribe confimation click/receive statistic command(s)
	$InRequest = trim($_SERVER['QUERY_STRING']);
	if(version_compare(phpversion(),"5.5.0","<"))
		$InRequest = mcrypt_cbc(MCRYPT_RIJNDAEL_128,$Password,base64_decode(urldecode($InRequest)),MCRYPT_DECRYPT,'amsstatinivector');
	else if(version_compare(phpversion(),"7.0.0","<"))
		{		
		$td = mcrypt_module_open (MCRYPT_RIJNDAEL_128, '', 'cbc', '');
		mcrypt_generic_init ($td, $Password, 'amsstatinivector');
		$InRequest = mdecrypt_generic($td, base64_decode(urldecode($InRequest)));
		mcrypt_generic_deinit ($td);
		mcrypt_module_close ($td); 
		}
	else if(extension_loaded('openssl'))
		$InRequest = openssl_decrypt(base64_decode(urldecode($InRequest)), 'AES-128-CBC', $Password, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, 'amsstatinivector');
	else
		{
		echo "Can't decrypt query: unable to initialize mcrypt or OpenSSL cryptographic extensions";
        	exit;	
		}
	if((strpos($InRequest,'amsclk')===false && strpos($InRequest,'amscmd')===false) || strpos($InRequest,'|{')===false)
		{
		echo "Unknown request type";
		exit;
		}
	if(strpos($InRequest,'amsclk')!==false)
		{
		// Traceable link click/opened message counter/(un)subscribe confimation click
		$InRequest = substr_replace($InRequest,'',0,7); 
		if(!mb_detect_encoding($InRequest, 'ASCII', true))
			{
			echo "Unable to decode URL !";
			exit;
			}
		$ParamsArray = explode("|{",$InRequest);
		foreach($ParamsArray as $InParam)
			{
			if(strpos($InParam,"PID=")===0)
				{
				$ProgID = trim(substr($InParam,4));
				if((strpos($ProgID,"AMS_")===false && strpos($ProgID,"MPC_")===false) || !is_numeric(substr($ProgID,4)))
					{
					echo "Unable to decode URL !";
					exit;
					}
				}
			else if(strpos($InParam,"GID=")===0)
				{
				$GroupID = trim(substr($InParam,4));
				if(!is_numeric($GroupID))
					{
					echo "Unable to decode URL !";
					exit;
					}
				}
			else if(strpos($InParam,"MLID=")===0)
				{
				$MailingID = trim(substr($InParam,5));
				if(!is_numeric($MailingID))
					{
					echo "Unable to decode URL !";
					exit;
					}
				}
			else if(strpos($InParam,"MSID=")===0)
				{
				$MessageID = trim(substr($InParam,5));
				if(!is_numeric($MessageID))
					{
					echo "Unable to decode URL !";
					exit;
					}	
				}
			else if(strpos($InParam,"CNTID=")===0)
				{
				$ContactID = trim(substr($InParam,6));
				if(!is_numeric($ContactID))
					{
					echo "Unable to decode URL !";
					exit;
					}
				}
			else if(strpos($InParam,"EML=")===0)
				$RcptEmail = trim(substr($InParam,4));
			else if(strpos($InParam,"RD=")===0)
				$RedirURL = trim(substr($InParam,3));
			else if(strpos($InParam,"UAction=")===0)
				{
				$UnsubcrubeClick = 1;
				$UnsubscribeAction = trim(substr($InParam,8));
				}
			}
		if($ProgID=="-1")
			{
			echo "Unknown request type";
			exit;
			}
		}
	else if(strpos($InRequest,'amscmd')!==false)
		{
		// MakeCopy/GetCopy commands
		$InRequest = substr_replace($InRequest,'',0,6); 
		$ParamsArray = explode("|{",$InRequest);
		foreach($ParamsArray as $InParam)
			{
			if(strpos($InParam,"PID=")===0)
				$ProgID = trim(substr($InParam,4));
			if(strpos($InParam,"MCPY=")===0)
				$MakeCopy = 1;
			else if(strpos($InParam,"GCPY=")===0)
				$GetCopy = 1;
			}
		if($ProgID=="-1" || ($MakeCopy==0 && $GetCopy==0))
			{
			echo "Unknown request type";
			exit;
			}
		}
	else
		{
		// should never be here
		echo "Unknown request type";
		exit;
		}
	}
//-----------------------------------------------------------------

function HtmlEntDecode($text)
{
$str = '';
$i = 0;
while ($i < strlen($text))
	{
	if ($i < strlen($text) - 1 && substr($text, $i, 2) == "&#")
		{
		$chr = '';
		$i += 2;
		while ($i < strlen($text) && substr($text, $i, 1) != ";")
			{
		        $chr .= substr($text, $i, 1);
                	$i++;
			}
		if (strlen($chr) > 0)
			{
	               	$str .= utf8_chr($chr);
	        	}
		}
	else
		{
	        $str .= substr($text, $i, 1);
	        }
	$i++;
	}
return $str;
}

//--------------------------------------------------------------------

function utf8_chr($code)
{
if($code<128) return chr($code);
else if($code<2048) return chr(($code>>6)+192).chr(($code&63)+128);
else if($code<65536) return chr(($code>>12)+224).chr((($code>>6)&63)+128).chr(($code&63)+128);
else if($code<2097152) return chr($code>>18+240).chr((($code>>12)&63)+128).chr(($code>>6)&63+128).chr($code&63+128);
}
//--------------------------------------------------------------------

if($MakeCopy == 1)
	{
	if(file_exists($ProgID.'.log'))
		{
		if(!copy($ProgID.'.log',$ProgID.'.out'))
			{
			echo "Error: Can't create output file. Permission denied.";
			exit;	
			}
		$LogFile = fopen($ProgID.'.log', 'w');
		if(!$LogFile)
			{
			echo "Error: Can't update input file. Permission denied.";
			exit;
			}
		flock($LogFile, 2); 
		ftruncate($LogFile,0);
		flock($LogFile, 3);
		fclose($LogFile);
		echo "cmd_ok";
		exit;
		}
	else
		{
		echo 'Error: No File';
		exit;
		}
	}
else if($GetCopy == 1)
	{
        if(file_exists($ProgID.'.out'))
		{
       	        $LogFile = fopen($ProgID.'.out', 'r');
		if(!$LogFile)
			{
			echo "Error: Cant open out file";
			exit;
			}
                flock($LogFile, 2);
                while(!feof($LogFile))
                	{
                        $Buffer = fgets($LogFile, 4096);
                        echo $Buffer;
                        }
                flock($LogFile, 3);
                fclose($LogFile);
		chmod($ProgID.'.log', 0755);
		echo "cmd_ok";
                exit;
                }
	else
            	{
                echo "Error: No File";
                exit;
                }
	}
else
	{
	$today = getdate() ;
	$LogFile = fopen($ProgID.'.log', 'ab');
	if(!$LogFile)
		{
		echo "Error: Can't open log file. Permission denied.";
		exit;
		}
	flock($LogFile, 2);
	if(stristr($ProgID,"AMS_"))
		{
		if($UnsubcrubeClick=="0")
			$OutString="$MailingID:$GroupID:$RcptEmail:$RedirURL|};".$today['year'].":".$today['mon'].":".$today['mday'].":".$today['hours'].":".$today['minutes']."\r\n";
		else
			{
			$OutString="$MailingID:$GroupID:$RcptEmail:Unsubscribe_Click:$UnsubscribeAction|};".$today['year'].":".$today['mon'].":".$today['mday'].":".$today['hours'].":".$today['minutes']."\r\n";
			echo $HtmlHead."<body BGCOLOR=\"#E6E6E6\"><div align=\"center\"><FONT color=\"#003399\"<br>$Unsubscribe_Link_Click</FONT></div></body></html>";
			}
		}
	else if(stristr($ProgID,"MPC_"))
		{
                if($FormName=="no_form")
			{
                        $OutString="Confirm_Data=$MessageID:".$today['year'].":".$today['mon'].":".$today['mday'].":".$today['hours'].":".$today['minutes'].":".base64_encode($ClientIP).";\r\n";
			if($RedirURL=="nourl")
				echo $HtmlHead."<body BGCOLOR=\"#E6E6E6\"><div align=\"center\"><FONT color=\"#003399\"<br>$Confirmation_Link_Click</FONT></div></body></html>";
			}	
                else
			{
			$OutString="Form_Data=$FormName:".HtmlEntDecode($Form_FullName).":$Form_Email:".$today['year'].":".$today['mon'].":".$today['mday'].":".$today['hours'].":".$today['minutes'].":".base64_encode($ClientIP).";\r\n";
			echo $HtmlHead."<body BGCOLOR=\"#E6E6E6\"><div align=\"center\"><FONT color=\"#003399\"<br>$Form_Submit_OK</FONT></div></body></html>";
			}
                }
	fwrite($LogFile,$OutString);
        fflush($LogFile);
	flock($LogFile, 3);
	fclose($LogFile);
        chmod($ProgID.'.log', 0755);
	}
if($RedirURL != "nourl")
	{
	if(!headers_sent())
		{
		if($RedirURL == "open_trace")
			{
			header('Content-Type: image/png');
			echo "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x00\x00\x25\xdb\x56\xca\x00\x00\x00\x03\x50\x4c\x54\x45\x00\x00\x00\xa7\x7a\x3d\xda\x00\x00\x00\x01\x74\x52\x4e\x53\x00\x40\xe6\xd8\x66\x00\x00\x00\x0a\x49\x44\x41\x54\x08\xd7\x63\x60\x00\x00\x00\x02\x00\x01\xe2\x21\xbc\x33\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";
			}
		else if(strpos(strtolower($RedirURL),"http://")===0 || strpos(strtolower($RedirURL),"https://")===0)
		        header("Location: $RedirURL");	
    	        exit;
	        }
        }

function CheckScriptInstallation()
{
$CheckRes=true;
echo $HtmlHead;
echo "Проверка установки и работоспособности скрипта...<br><br>";
echo "Версия PHP: ".phpversion()."<br><br>";
echo "Расширение mbstring: ";
if(extension_loaded("mbstring"))
	echo "OK<br>";
else
	{
	echo "Не установлено ! Требуется включить расширение mbstring в настройках РHP или в личном кабинете хостера<br>";
	$CheckRes=false;
	}
if( version_compare(phpversion(), "7.0.0", "<") )
    {
	echo "Расширение mcrypt: ";
	if(extension_loaded("mcrypt"))
		echo "OK<br>";
	else
		{
		echo "не установлено ! Требуется включить расширение mcrypt в настройках РHP или в личном кабинете хостера<br>";
		$CheckRes=false;
		}
	if(version_compare(phpversion(),"5.5.0","<"))
		{
		echo "Функция mcrypt_cbc: ";
		if(function_exists("mcrypt_cbc"))
			echo "OK<br>";
		else
			{
			echo "Не найдена ! Проверьте настройки PHP: требуется расширение mcrypt для поддержки криптографии<br>";
			$CheckRes=false;
			}
		}
	else
		{
		echo "Функция mcrypt_cbc: ";
		if(function_exists("mdecrypt_generic"))
			echo "OK<br>";
		else
			{
			echo "Не найдена ! Проверьте настройки PHP: требуется расширение mcrypt для поддержки криптографии<br>";
			$CheckRes=false;
			}
		}
	}
else
    {
    echo "Расширение openssl: ";
    if(extension_loaded("openssl"))
		echo "OK<br>";
    else
		{
        echo "не установлено ! Требуется включить расширение openssl в настройках РHP или в личном кабинете хостера<br>";
        $CheckRes = false;
        }
    }
echo "Функция mb_detect_encoding: ";
if(function_exists("mb_detect_encoding"))
	echo "OK<br>";
else
	{
	echo "Не найдена ! Проверьте настройки PHP: требуется расширение mbstring !<br>";	
	$CheckRes=false;
	}
echo "<br>";
echo "Пытаемся создать файл test.log... ";
$TestFile = fopen('test.log', 'w');
if($TestFile)
	{
	echo "OK<br>";
	echo "Пытаемся записать данные в файл...";
	if(fwrite($TestFile,"this is a test")===false)
		{
		echo "Не удача ! Проверьте, что для папки, в которой расположен скрипт, а так же для самого файла скрипта назначены права доступа 755 !<br>";
		$CheckRes=false;
		}
	else
		echo "OK<br>";
	fclose($TestFile);
	echo "Пытаемся скопировать test.log -> test.out...";
	if(copy('test.log','test.out')===false)
		{
		echo "Не удача ! Проверьте, что для папки, в которой расположен скрипт, а так же для самого файла скрипта назначены права доступа 755 !<br>";
		$CheckRes=false;
		}
	else
		echo "OK<br>";
	}	
else
	{
	echo "Не удача ! Проверьте, что для папки, в которой расположен скрипт, а так же для самого файла скрипта назначены права доступа 755 !<br>";
	$CheckRes=false;
	}
if(file_exists('test.log'))
	unlink('test.log');
if(file_exists('test.out'))
	unlink('test.out');
echo "<br>";
if($CheckRes==true)
	echo "Проверка прошла успешно, скрипт установлен и функционирует правильно !<br>";
else
	echo "В процессе проверки возникли ошибки. Необходимо их исправить прежде чем скрипт будет готов к использованию !";
echo "</HTML>";
}
?>