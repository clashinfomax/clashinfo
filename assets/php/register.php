<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Récupérer les données du formulaire
    $prenom = trim($_POST['prenom']);
    $nom = trim($_POST['nom']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    $errors = [];

    // Valider l'email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "L'adresse email n'est pas valide.";
    }

    // Vérifier la correspondance des mots de passe
    if ($password !== $confirm_password) {
        $errors[] = "Les mots de passe ne correspondent pas.";
    }

    // Valider la longueur du mot de passe (au moins 8 caractères)
    if (strlen($password) < 8) {
        $errors[] = "Le mot de passe doit contenir au moins 8 caractères.";
    }

    // Si pas d'erreurs, on continue
    if (empty($errors)) {
        try {
            // Connexion à la base de données avec PDO
            $db = new PDO('mysql:host=localhost;dbname=clashofmax', 'root', '');
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Vérifier si l'email existe déjà
            $stmt = $db->prepare("SELECT * FROM users WHERE email = ?");
            $stmt->execute([$email]);

            if ($stmt->rowCount() > 0) {
                $errors[] = "L'adresse email est déjà utilisée.";
            } else {
                // Si l'email n'existe pas, on hache le mot de passe
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                // Insertion de l'utilisateur dans la base de données
                $stmt = $db->prepare("INSERT INTO users (prenom, nom, email, password) VALUES (?, ?, ?, ?)");
                if ($stmt->execute([$prenom, $nom, $email, $hashed_password])) {
                    echo "<p>Inscription réussie ! Vous pouvez maintenant vous <a href='signin.html'>connecter</a>.</p>";
                } else {
                    $errors[] = "Une erreur est survenue lors de l'inscription. Veuillez réessayer plus tard.";
                }
            }
        } catch (PDOException $e) {
            $errors[] = "Erreur de connexion à la base de données : " . $e->getMessage();
        }
    }

    // Afficher les erreurs s'il y en a
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo "<p style='color:red;'>$error</p>";
        }
    }
}
?>
