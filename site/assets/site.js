// Click a screenshot to view it full size.
(() => {
  const dialog = document.createElement('dialog');
  dialog.className = 'lightbox';
  dialog.innerHTML = '<button class="close" aria-label="Close">×</button><img alt=""><p></p>';
  document.body.append(dialog);
  const img = dialog.querySelector('img');
  const caption = dialog.querySelector('p');

  document.querySelectorAll('.shot button').forEach((button) => {
    button.addEventListener('click', () => {
      const source = button.querySelector('img');
      img.src = source.currentSrc || source.src;
      img.alt = source.alt;
      caption.textContent = source.alt;
      dialog.showModal();
    });
  });
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog || event.target.classList.contains('close')) dialog.close();
  });
})();
