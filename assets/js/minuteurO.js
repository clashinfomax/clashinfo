document.getElementById('main-category').addEventListener('change', function() {
    const subCategorySelection = document.getElementById('sub-category-selection');
    const selectedCategory = this.value;

    let imagesHTML = '';

    if (selectedCategory === 'heroes') {
        imagesHTML = `
          <label class="category-option">
                <input type="radio" name="category" value="championne" required>
                <img src="assets/images/clash of clanO/robotvolant.png" alt="championne" class="img-thumbnail" width="50">
            </label>
         
            <label class="category-option">
                <input type="radio" name="category" value="roi_des_barbars" required>
                <img src="assets/images/clash of clanO/megerobot.png" alt="roi des barbares" class="img-thumbnail" width="50">
            </label>`;
    } else if (selectedCategory === 'defense') {
        imagesHTML = `
             <label class="category-option">
                <input type="radio" name="category" value="Tour d'Archers" required>
                <img src="assets/images/clash of clanO/tour_archer.png" alt="Tour d'Archers" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="tesla" required>
                <img src="assets/images/clash of clanO/tesla.png" alt="tesla" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="pétard" required>
                <img src="assets/images/clash of clanO/petard.png" alt="pétard" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="multicanon" required>
                <img src="assets/images/clash of clanO/multicanon.png" alt="multicanon" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="mega tesla" required>
                <img src="assets/images/clash of clanO/mega_tesla.png" alt="mega tesla" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="lance lave" required>
                <img src="assets/images/clash of clanO/lance_lave.png" alt="lance lave" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="double canon" required>
                <img src="assets/images/clash of clanO/doublecanon.png" alt="double canon" class="img-thumbnail" width="50">
            </label>
           
            <label class="category-option">
                <input type="radio" name="category" value="canon geant" required>
                <img src="assets/images/clash of clanO/canon_geant.png" alt="canon geant" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="canon" required>
                <img src="assets/images/clash of clanO/canon.png" alt="canon" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="broyeur" required>
                <img src="assets/images/clash of clanO/broyeur.png" alt="broyeur" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="bombe" required>
                <img src="assets/images/clash of clanO/bombe.png" alt="bombe" class="img-thumbnail" width="50">
            </label>
               <label class="category-option">
                <input type="radio" name="category" value="Rotissoire" required>
                <img src="assets/images/clash of clanO/Rotissoire.png" alt="Rotissoire" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Poste de garde" required>
                <img src="assets/images/clash of clanO/Poste_de_garde.png" alt="Poste de garde" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="bombe aérienne" required>
                <img src="assets/images/clash of clanO/bombe aerienne.png" alt="bombe aérienne" class="img-thumbnail" width="50">
            </label>`;
    } else if (selectedCategory === 'structures') {
        imagesHTML = `
          
            <label class="category-option">
                <input type="radio" name="category" value="Cabane de soins" required>
                <img src="assets/images/clash of clanO/Cabane_de_soins.png" alt="Cabane de soins" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Caserne des ouvriers" required>
                <img src="assets/images/clash of clanO/Caserne_des_ouvriers.png" alt="Caserne des ouvriers" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Laboratoire astral" required>
                <img src="assets/images/clash of clanO/Laboratoire_astral.png" alt="Laboratoire astral" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="maison des ouvriers" required>
                <img src="assets/images/clash of clanO/maison_des_ouvriers.png" alt="maison des ouvriers" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Mine de gemmes" required>
                <img src="assets/images/clash of clanO/Mine_de_gemmes.png" alt="Mine de gemmes" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="mine or" required>
                <img src="assets/images/clash of clanO/mine_or.png" alt="mine or" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Réserve or" required>
                <img src="assets/images/clash of clanO/Réserve_or.png" alt="Réserve or" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Reservoir elixir" required>
                <img src="assets/images/clash of clanO/Reservoir_elixir.png" alt="Reservoir elixir" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Tour de horloge" required>
                <img src="assets/images/clash of clanO/Tour_de_horloge.png" alt="Tour de horloge" class="img-thumbnail" width="50">
            </label>`;
    }
    else if (selectedCategory === 'troupe') {
        imagesHTML = `
           
            <label class="category-option">
                <input type="radio" name="category" value="Sorcière de la nuit" required>
                <img src="assets/images/clash of clanO/sorciere.png" alt="Sorcière de la nuit" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="sorcier pyroélectrique" required>
                <img src="assets/images/clash of clanO/sorcier.png" alt="sorcier pyroélectrique" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Super P.E.K.K.A " required>
                <img src="assets/images/clash of clanO/peka.png" alt="Super P.E.K.K.A " class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Géant boxeur" required>
                <img src="assets/images/clash of clanO/geant.png" alt="Géant boxeur" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Bêta-gargouille" required>
                <img src="assets/images/clash of clanO/gargouille.png" alt="Bêta-gargouille" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Chevaucheur du ciel" required>
                <img src="assets/images/clash of clanO/cochon.png" alt="Chevaucheur du ciel" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Charrette à canon" required>
                <img src="assets/images/clash of clanO/charrette.png" alt="Charrette à canon" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Bombardier" required>
                <img src="assets/images/clash of clanO/bombardier.png" alt="Bombardier" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Bébé dragon" required>
                <img src="assets/images/clash of clanO/bb_dragon.png" alt="Bébé dragon" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="barbare enragé" required>
                <img src="assets/images/clash of clanO/barbar.png" alt="barbare enragé" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="Ballon livreur" required>
                <img src="assets/images/clash of clanO/ballon.png" alt="Ballon livreur" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="archers furtive" required>
                <img src="assets/images/clash of clanO/archert.png" alt="archers furtive" class="img-thumbnail" width="50">
            </label>`;
    }

    subCategorySelection.innerHTML = imagesHTML;
});
