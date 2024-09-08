document.getElementById('main-category').addEventListener('change', function() {
    const subCategorySelection = document.getElementById('sub-category-selection');
    const selectedCategory = this.value;

    let imagesHTML = '';

    if (selectedCategory === 'heroes') {
        imagesHTML = `
            <label class="category-option">
                <input type="radio" name="category" value="championne" required>
                <img src="assets/images/clash of clans/championne.png" alt="championne" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="grand_gardien" required>
                <img src="assets/images/clash of clans/grand_gardien.png" alt="grand gardien" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="reine_des_archers" required>
                <img src="assets/images/clash of clans/reine_des_archers.png" alt="reine des archers" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="roi_des_barbars" required>
                <img src="assets/images/clash of clans/roi_des_barbars.png" alt="roi des barbares" class="img-thumbnail" width="50">
            </label>`;
    } else if (selectedCategory === 'defense') {
        imagesHTML = `
            <label class="category-option">
                <input type="radio" name="category" value="aigle_artilleur" required>
                <img src="assets/images/clash of clans/aigle_artilleur.png" alt="aigle artilleur" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="arc_x" required>
                <img src="assets/images/clash of clans/arc_x.png" alt="arc x" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="canon" required>
                <img src="assets/images/clash of clans/canon.png" alt="canon" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="mortier" required>
                <img src="assets/images/clash of clans/mortier.png" alt="mortier" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="tesla" required>
                <img src="assets/images/clash of clans/tesla.png" alt="tesla" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="bombe" required>
                <img src="assets/images/clash of clans/bombe.png" alt="bombe" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="defense_anti_aerienne" required>
                <img src="assets/images/clash of clans/defense_anti_aerienne.png" alt="défense anti-aérienne" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="tour_a_bombe" required>
                <img src="assets/images/clash of clans/tour_a_bombe.png" alt="tour à bombe" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="tour_de_l_enfer" required>
                <img src="assets/images/clash of clans/tour_de_enfer.png" alt="tour de l'enfer" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="tour_sorcier" required>
                <img src="assets/images/clash of clans/tour_sorcier.png" alt="tour sorcier" class="img-thumbnail" width="50">
            </label>
                  <label class="category-option">
                <input type="radio" name="category" value="souffleur" required>
                <img src="assets/images/clash of clans/souffleur.png" alt="souffleur" class="img-thumbnail" width="50">
            </label>
                <label class="category-option">
                <input type="radio" name="category" value="catapulte" required>
                <img src="assets/images/clash of clans/catapulte.png" alt="catapulte" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="tour_archers" required>
                <img src="assets/images/clash of clans/tour_archers.png" alt="tour archers" class="img-thumbnail" width="50">
            </label>`;
    } else if (selectedCategory === 'structures') {
        imagesHTML = `
            <label class="category-option">
                <input type="radio" name="category" value="hdv" required>
                <img src="assets/images/clash of clans/hdv.png" alt="hdv" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="camp_militaire" required>
                <img src="assets/images/clash of clans/camp_militaire.png" alt="camp militaire" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="caserne" required>
                <img src="assets/images/clash of clans/caserne.png" alt="caserne" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="caserne_noire" required>
                <img src="assets/images/clash of clans/caserne_noire.png" alt="caserne noire" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="laboratoire" required>
                <img src="assets/images/clash of clans/laboratoire.png" alt="laboratoire" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="chateau_de_clan" required>
                <img src="assets/images/clash of clans/chateau_de_clan.png" alt="chateau de clan" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="extracteur_elexir" required>
                <img src="assets/images/clash of clans/extracteur_elexir.png" alt="extracteur élixir" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="foreuse_elixir" required>
                <img src="assets/images/clash of clans/foreuse_elixir.png" alt="foreuse d'élixir" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="forgeron" required>
                <img src="assets/images/clash of clans/forgeron.png" alt="forgeron" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="mine_or" required>
                <img src="assets/images/clash of clans/mine_or.png" alt="mine d'or" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="reservoir_or" required>
                <img src="assets/images/clash of clans/reservoir_or.png" alt="réservoir d'or" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="reservoir_elixir" required>
                <img src="assets/images/clash of clans/reservoir_elexir.png" alt="réservoir d'élixir" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="reservoir_elixir_noir" required>
                <img src="assets/images/clash of clans/reservoir_elexir_noir.png" alt="réservoir d'élixir noir" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="usine_de_sorts_noire" required>
                <img src="assets/images/clash of clans/usine_de_sorts_noire.png" alt="usine_de_sorts_noire" class="img-thumbnail" width="50">
            </label>
            <label class="category-option">
                <input type="radio" name="category" value="usine_de_sorts" required>
                <img src="assets/images/clash of clans/usine_de_sorts.png" alt="usine de sorts" class="img-thumbnail" width="50">
            </label>`;
    }

    subCategorySelection.innerHTML = imagesHTML;
});
