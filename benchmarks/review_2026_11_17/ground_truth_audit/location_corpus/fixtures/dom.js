export function render(node, userInput) {
  node.innerHTML = userInput;
  node.innerHTML = '';
  node.innerHTML = null;
  node.textContent = userInput;
}
