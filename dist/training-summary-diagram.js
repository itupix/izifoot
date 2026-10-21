"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseSummaryDiagram = parseSummaryDiagram;
exports.drawSummaryDiagram = drawSummaryDiagram;
// Existing web/iOS diagram coordinates are already rotated by the editor.
function parseSummaryDiagram(input) {
    const empty = { width: 600, height: 380, frames: [], invalid: true };
    try {
        const data = typeof input === 'string' ? JSON.parse(input) : input;
        if (!data || typeof data !== 'object')
            return empty;
        const turns = Number(data.rotationQuarterTurns);
        const portrait = Number.isFinite(turns) ? Math.abs(Math.trunc(turns) % 2) === 1 : data.orientation === 'portrait';
        const width = portrait ? 380 : 600, height = portrait ? 600 : 380;
        const point = (raw) => {
            if (!raw || !Number.isFinite(Number(raw.x)) || !Number.isFinite(Number(raw.y)))
                return null;
            return { x: Math.max(5, Math.min(width - 5, Number(raw.x))), y: Math.max(5, Math.min(height - 5, Number(raw.y))) };
        };
        let invalid = false;
        const frames = Array.isArray(data.frames) && data.frames.length ? data.frames.slice(0, 10) : Array.isArray(data.items) ? [{ items: data.items }] : null;
        if (!frames)
            return empty;
        const legacy = !(Array.isArray(data.frames) && data.frames.length);
        const normalized = frames.flatMap((frame, index) => {
            if (!frame || !Array.isArray(frame.items)) {
                invalid = true;
                return [];
            }
            const items = frame.items.flatMap((item) => {
                if (!item || !['player', 'cone', 'cup', 'ball', 'post', 'arrow'].includes(item.type)) {
                    invalid = true;
                    return [];
                }
                if (item.type === 'arrow') {
                    const from = point(item.from), to = point(item.to);
                    if (!from || !to) {
                        invalid = true;
                        return [];
                    }
                    return [{ type: 'arrow', x: 0, y: 0, from, to }];
                }
                const position = point(item);
                if (!position) {
                    invalid = true;
                    return [];
                }
                return [{ ...position, type: item.type, label: typeof item.label === 'string' ? item.label : '', color: typeof item.color === 'string' ? item.color : (item.side === 'away' ? 'red' : 'blue') }];
            });
            return items.length ? [{ step: legacy ? null : index + 1, name: typeof frame.name === 'string' ? frame.name : '', items }] : [];
        });
        return { width, height, frames: normalized, invalid };
    }
    catch {
        return empty;
    }
}
function drawSummaryDiagram(doc, diagram, frame, x, y, width, height) {
    const scale = Math.min(width / diagram.width, height / diagram.height);
    doc.save().translate(x + (width - diagram.width * scale) / 2, y).scale(scale);
    doc.rect(0, 0, diagram.width, diagram.height).fill('#f8fff8');
    doc.roundedRect(5, 5, diagram.width - 10, diagram.height - 10, 8).fillAndStroke('#ffffff', '#c7e2c7');
    const portrait = diagram.height > diagram.width;
    doc.strokeColor('#c7e2c7').lineWidth(1).dash(4, { space: 4 });
    if (portrait)
        doc.moveTo(5, diagram.height / 2).lineTo(diagram.width - 5, diagram.height / 2).stroke();
    else
        doc.moveTo(diagram.width / 2, 5).lineTo(diagram.width / 2, diagram.height - 5).stroke();
    doc.undash();
    if (portrait) {
        doc.rect(diagram.width / 2 - 60, 5, 120, 40).stroke();
        doc.rect(diagram.width / 2 - 60, diagram.height - 45, 120, 40).stroke();
    }
    else {
        doc.rect(5, diagram.height / 2 - 60, 40, 120).stroke();
        doc.rect(diagram.width - 45, diagram.height / 2 - 60, 40, 120).stroke();
    }
    // Keep edge items and long player labels inside the field.
    doc.rect(0, 0, diagram.width, diagram.height).clip();
    const colors = { blue: '#3b82f6', red: '#ef4444', yellow: '#eab308', green: '#22c55e', orange: '#f97316' };
    for (const item of frame.items) {
        const { x: px, y: py } = item;
        doc.lineWidth(1).undash();
        if (item.type === 'arrow') {
            const from = item.from, to = item.to, angle = Math.atan2(to.y - from.y, to.x - from.x);
            doc.moveTo(from.x, from.y).lineTo(to.x, to.y).lineWidth(2).stroke('#111827');
            if (from.x !== to.x || from.y !== to.y)
                doc.moveTo(to.x, to.y).lineTo(to.x - 8 * Math.cos(angle - Math.PI / 6), to.y - 8 * Math.sin(angle - Math.PI / 6)).lineTo(to.x - 8 * Math.cos(angle + Math.PI / 6), to.y - 8 * Math.sin(angle + Math.PI / 6)).closePath().fill('#111827');
        }
        else if (item.type === 'player') {
            doc.circle(px, py, 14).fillAndStroke(Object.prototype.hasOwnProperty.call(colors, item.color || 'blue') ? colors[item.color || 'blue'] : colors.blue, '#111827');
            if (item.label)
                doc.font('Bold').fontSize(12).fillColor('#ffffff').text(item.label, px - 25, py - 7, { width: 50, align: 'center', lineBreak: false });
        }
        else if (item.type === 'cone')
            doc.moveTo(px, py - 10).lineTo(px - 10, py + 10).lineTo(px + 10, py + 10).closePath().fillAndStroke('#f97316', '#7c2d12');
        else if (item.type === 'cup') {
            doc.circle(px, py, 10).fillAndStroke('#fde047', '#a16207');
            doc.circle(px, py, 4).fillAndStroke('#fffbeb', '#a16207');
        }
        else if (item.type === 'post')
            doc.roundedRect(px - 4, py - 16, 8, 32, 2).fillAndStroke('#94a3b8', '#334155');
        else if (item.type === 'ball') {
            doc.circle(px, py, 10).fillAndStroke('#ffffff', '#111827');
            doc.moveTo(px - 5, py).lineTo(px + 5, py).moveTo(px, py - 5).lineTo(px, py + 5).stroke('#111827');
        }
    }
    doc.restore();
}
