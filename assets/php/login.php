<?php
session_start();

$error = ""; // Initialiser la variable d'erreur

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Récupération des données du formulaire
    $email_or_username = $_POST['email_or_username'];
    $password = $_POST['password'];

    // Connexion à la base de données
    $conn = new mysqli('localhost', 'votre_utilisateur', 'votre_mot_de_passe', 'votre_base_de_donnees');

    // Vérifier la connexion
    if ($conn->connect_error) {
        die("Erreur de connexion : " . $conn->connect_error);
    }

    // Requête pour vérifier si l'utilisateur existe
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ? OR username = ?");
    $stmt->bind_param("ss", $email_or_username, $email_or_username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        // Vérification du mot de passe
        if (password_verify($password, $user['password'])) {
            // Connexion réussie
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            header("Location: index.html"); // Redirige vers la page d'accueil après connexion
            exit();
        } else {
            // Mot de passe incorrect
            $error = "Mot de passe incorrect.";
        }
    } else {
        // Aucun utilisateur trouvé avec cet email ou pseudo
        $error = "Aucun utilisateur trouvé avec cet email ou pseudo.";
    }

    $stmt->close();
    $conn->close();
}
?>
