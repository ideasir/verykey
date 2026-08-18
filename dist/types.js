"use strict";
// VeryKey - 类型定义
Object.defineProperty(exports, "__esModule", { value: true });
exports.LEVEL_PREFIX = exports.VAR_SUFFIX = exports.VAR_PREFIX = exports.LEVEL_NAMES = exports.Level = void 0;
exports.maskValue = maskValue;
exports.validateLevel = validateLevel;
/** 权限等级 */
var Level;
(function (Level) {
    Level[Level["Temp"] = 0] = "Temp";
    Level[Level["Normal"] = 1] = "Normal";
    Level[Level["Important"] = 2] = "Important";
    Level[Level["Critical"] = 3] = "Critical";
})(Level || (exports.Level = Level = {}));
exports.LEVEL_NAMES = ['Temp', 'Normal', 'Important', 'Critical'];
/** 变量引用格式 */
exports.VAR_PREFIX = '$VERYKEY:';
exports.VAR_SUFFIX = '$';
/** Token 前缀映射 */
exports.LEVEL_PREFIX = {
    [Level.Temp]: 'vk_temp_',
    [Level.Normal]: 'vk_norm_',
    [Level.Important]: 'vk_imp_',
    [Level.Critical]: 'vk_crit_',
};
/** 脱敏显示 */
function maskValue(value) {
    const len = value.length;
    if (len <= 3)
        return '***';
    if (len <= 6)
        return value[0] + '***' + value[len - 1];
    if (len <= 12)
        return value.slice(0, 2) + '****' + value.slice(-2);
    if (len <= 20)
        return value.slice(0, 4) + '****' + value.slice(-4);
    return value.slice(0, 6) + '****' + value.slice(-6);
}
/** 校验权限等级 */
function validateLevel(level) {
    return Number.isInteger(level) && level >= 0 && level <= 3;
}
//# sourceMappingURL=types.js.map