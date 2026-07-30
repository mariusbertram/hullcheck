'use strict';

const IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,510}$/;

function isValidImageRef(image) {
  return typeof image === 'string' && image.length > 0 && IMAGE_RE.test(image);
}

module.exports = { IMAGE_RE, isValidImageRef };
