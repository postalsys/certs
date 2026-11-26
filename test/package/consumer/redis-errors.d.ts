// ioredis 6.1.0 ships declarations that import 'redis-errors', but lists @types/redis-errors as a
// devDependency only, so a strict consumer cannot resolve it. This stands in for the missing types
// without skipLibCheck, which would also stop checking the declarations this package ships.
declare module 'redis-errors';
