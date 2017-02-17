<?php
header('Content-Type: text/html; charset=utf-8');
//variable globale
$texte_dechiffrer = $texte_chiffrer = $chiffrementErr = "";

 //Securité pour empecher certaines intrusion xss
        function test_input($data) {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
      if(empty($_POST["chiffrement"])){
         $chiffrementErr = "Veuillez completer le champs avant d'envoyer votre texte";
         }else{
          
          //le message securiser
          $message_a_chiffrer = test_input($_POST["chiffrement"]);
          
         $module_chiffrement = mcrypt_module_open('rijndael-256', '', 'cbc', '');
            
            /* Crée le VI et détermine la taille de la clé */
          $vecteur_iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($module_chiffrement), MCRYPT_DEV_RANDOM);
          $taille_vecteur_iv = mcrypt_enc_get_key_size($module_chiffrement);
                       
            /* Crée la clé */
          $cle = "Clé non securisé";
            
            /* Intialise le chiffrement */
          mcrypt_generic_init($module_chiffrement, $cle, $vecteur_iv );

            /* Chiffre les données */
          $chiffrer = mcrypt_generic($module_chiffrement, $message_a_chiffrer );
          $texte_chiffrer = $chiffrer;

            /* Libère le gestionnaire de chiffrement pour pouvoir le reutiliser pour le dechiffrement*/
          mcrypt_generic_deinit($module_chiffrement);


            /* Initialise le module de chiffrement pour le déchiffrement */
          mcrypt_generic_init($module_chiffrement, $cle, $vecteur_iv );

            /* Déchiffre les données */
          $dechiffrer = mdecrypt_generic($module_chiffrement, $chiffrer);
          $texte_dechiffrer = $dechiffrer;
          
            /* Libère le gestionnaire de déchiffrement, et ferme le module tres important*/
          mcrypt_generic_deinit($module_chiffrement);
          mcrypt_module_close($module_chiffrement);
   
      }
}
    
?>
<!DOCTYPE html>
<html lang="fr">
   
    <head>
        <meta charset="utf-8">
        <title>Exemple de chiffrement</title>
        <style>
            .error {color: #FF0000;}
        </style>
    </head>
    <body>
   <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">
        <p>
           <p><textarea rows="4" cols="50" name="chiffrement" placeholder="Texte a chiffrer"></textarea>
           <span class="error">* <?php echo $chiffrementErr;?></span></p>
           <p><input type="submit" name="envoit" value="Chiffrement" /></p>
           <p><span><?php echo "Message chiffré = ".$texte_chiffrer;?></span></p>
           <p><span><?php echo "Message déchiffré = ".$texte_dechiffrer;?></span></p>
       </p>
       
       <p><h1 class ="error">Pour enregistrer dans la bdd</h1></p>
       
       <p>Il faut utiliser un type Blob afin de proceder à l'enregistrement.
       </br>Pour le dechiffrement a partir d'une bdd il faudra utiliser la fonction rtrim(), car 4 caracteres sont ajouté par le type blob et cela peut nuire à l'utilisation.
       </br>exemple : $dechiffrement =  rtrim($dechiffrement);</p>

       <p>Pour chiffrer des dossiers images etc etc, utiliser  <q> l'attribut : accept="file_extension|audio/*|video/*|image/*|media_type"</q> dans l'input, et type Blob pour stocker dans la bdd. </p>

       <p class ="error">Cette Fonction est deprecier en php 7.2.0, Je feurai un exemple avec Le module OpenSSl qui est destiner a remplacer mcrypt</p>

       <p><a href="https://secure.php.net/manual/en/migration71.deprecated.php">Lien d'information</a></p>


       <p><a href="https://secure.php.net/manual/fr/book.openssl.php">Lien vers OpenSSL</a></p>


 
    </body>
</html>
