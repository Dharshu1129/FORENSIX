document.addEventListener('DOMContentLoaded', function () {
    const quickSearchButtons = document.querySelectorAll('.btn-quick-entity');
    const searchInput = document.getElementById('entity-search-input');

    if (quickSearchButtons && searchInput) {
        quickSearchButtons.forEach(btn => {
            btn.addEventListener('click', function () {
                const term = this.getAttribute('data-entity');
                if (term) {
                    searchInput.value = term;
                    searchInput.form.submit();
                }
            });
        });
    }
});
