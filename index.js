'use strict';

/**
 * Dependencies
 */
const Promise = require('bluebird');
const jwt = require('jsonwebtoken');
const errors = require('meanie-express-error-handling');
const InvalidTokenError = errors.InvalidTokenError;
const ExpiredTokenError = errors.ExpiredTokenError;

/**
 * Check if token config is valid
 */
function isValidConfig(config) {
  if (!config.secret || !config.audience || !config.issuer) {
    return false;
  }
  return true;
}

/**
 * Defaults and registered token types
 */
const defaults = {};
const TypesMap = new Map();

/**
 * Module export
 */
const service = module.exports = {

  /**
   * Expose error types
   */
  InvalidTokenError,
  ExpiredTokenError,

  /**************************************************************************
   * Generation and validation
   ***/

  /**
   * Generate a token
   */
  generate(payload, config) {

    //If number given as config, use as expiration value
    if (typeof config === 'number') {
      config = {expiresIn: config};
    }

    //Extend default config
    config = service.mergeConfig(config);

    //Extract secret (removes it from the config object)
    const secret = service.extractSecret(config);

    //Return signed token
    return jwt.sign(payload || {}, secret, config);
  },

  /**
   * Validate a token
   */
  validate(token, config) {

    //Extend default config
    config = service.mergeConfig(config);

    //Extract secret (removes it from the config object)
    const secret = service.extractSecret(config);

    //Return as promise
    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, config, (error, payload) => {
        if (!error) {
          return resolve(payload);
        }
        if (error.name === 'TokenExpiredError') {
          error = new ExpiredTokenError(error.message);
        }
        else {
          error = new InvalidTokenError(error.message);
        }
        return reject(error);
      });
    });
  },

  /**************************************************************************
   * Types handling
   ***/

  /**
   * Pre-register token types
   */
  registerType(type, config) {

    //Invalid input
    if (!type) {
      throw new Error('Must specify type or types object map');
    }

    //Handle object maps
    if (typeof type === 'object') {
      for (const key in type) {
        if (type.hasOwnProperty(key)) {
          service.register(key, type[key]);
        }
      }
      return;
    }

    //Invalid input
    if (typeof type !== 'string') {
      throw new Error('Must specify string type');
    }

    //Extend with default configuration and validate
    config = service.mergeConfig(config);
    if (!isValidConfig(config)) {
      throw new Error('Invalid token configuration for type `' + type + '`');
    }

    //Store in map
    TypesMap.set(type, config);
  },

  /**
   * Generate a token of a specific type
   */
  generateType(type, claims) {
    const config = service.getType(type);
    return service.generate(claims, config);
  },

  /**
   * Validate a token of a specific type
   */
  validateType(type, token) {
    const config = service.getType(type);
    return service.validate(token, config);
  },

  /**
   * Get config for a given type
   */
  getType(type) {

    //Check if type exists
    if (!TypesMap.has(type)) {
      throw new Error('Unknown token type `' + type + '`');
    }

    //Get config (is already merged with defaults)
    return TypesMap.get(type);
  },

  /**************************************************************************
   * Helpers
   ***/

  /**
   * Set defaults
   */
  setDefaults(config) {
    Object.assign(defaults, config);
  },

  /**
   * Merge given configuration with defaults
   */
  mergeConfig(config) {
    return Object.assign({}, defaults, config || {});
  },

  /**
   * Extract secret from configuration object
   */
  extractSecret(config) {
    const secret = config.secret || '';
    delete config.secret;
    return secret;
  },
};
