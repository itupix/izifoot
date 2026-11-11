"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validAttendanceMonth = validAttendanceMonth;
exports.attendanceMonthInSeason = attendanceMonthInSeason;
exports.monthlyAttendancePlayers = monthlyAttendancePlayers;
exports.renderMonthlyAttendancePdf = renderMonthlyAttendancePdf;
const pdfkit_1 = __importDefault(require("pdfkit"));
function validAttendanceMonth(value) {
    return typeof value === 'string' && /^\d{4}-(0[1-9]|1[0-2])$/.test(value) && !value.startsWith('0000-');
}
function parisMonth(date) {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit' }).formatToParts(new Date(date));
    return `${parts.find(p => p.type === 'year').value}-${parts.find(p => p.type === 'month').value}`;
}
function attendanceMonthInSeason(month, season) {
    return validAttendanceMonth(month) && month >= parisMonth(season.startDate) && month <= parisMonth(season.endDate);
}
function monthlyAttendancePlayers(report) {
    const playerName = (p) => [p.first_name, p.last_name].filter(Boolean).join(' ') || p.name;
    return [...report.players].map(p => ({ ...p, displayName: playerName(p) })).sort((a, b) => a.displayName.localeCompare(b.displayName, 'fr', { sensitivity: 'base' }) || a.id.localeCompare(b.id));
}
function renderMonthlyAttendancePdf(report, teamName, month) {
    if (!attendanceMonthInSeason(month, report.season))
        return Promise.reject(new Error('Month is outside the current season'));
    return new Promise((resolve, reject) => {
        const doc = new pdfkit_1.default({ size: 'A4', layout: 'landscape', margin: 36, bufferPages: true, info: { Title: 'Présences aux entraînements' } });
        doc.registerFont('Body', require.resolve('dejavu-fonts-ttf/ttf/DejaVuSans.ttf'));
        doc.registerFont('Bold', require.resolve('dejavu-fonts-ttf/ttf/DejaVuSans-Bold.ttf'));
        const buffers = [];
        doc.on('data', (chunk) => buffers.push(chunk));
        doc.on('error', reject);
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        const trainings = report.trainings.filter(t => t.month === month).sort((a, b) => a.date.localeCompare(b.date) || a.id.localeCompare(b.id));
        const players = monthlyAttendancePlayers(report);
        const groups = Array.from({ length: Math.max(1, Math.ceil(trainings.length / 5)) }, (_, i) => trainings.slice(i * 5, i * 5 + 5));
        const monthTitle = new Intl.DateTimeFormat('fr-FR', { month: 'long', year: 'numeric', timeZone: 'Europe/Paris' }).format(new Date(`${month}-15T12:00:00Z`));
        const margin = 36, width = doc.page.width - margin * 2, rateWidth = 68, dateWidth = 72;
        const label = (value, x, y, w, size = 10, bold = false, align = 'left') => {
            doc.font(bold ? 'Bold' : 'Body').fontSize(size).fillColor('#203129').text(value, x, y, { width: w, height: 30, ellipsis: true, lineBreak: false, align });
        };
        const marker = (status, x, y) => {
            if (['PRESENT', 'ABSENT', 'NOT_APPLICABLE'].includes(status)) {
                doc.circle(x, y, 4).fill(status === 'PRESENT' ? '#16803C' : status === 'ABSENT' ? '#C93434' : '#929AA3');
            }
            else if (status === 'UNRECORDED') {
                doc.circle(x, y, 4).lineWidth(1.2).strokeColor('#556273').stroke();
            }
            else if (status === 'UPCOMING') {
                doc.circle(x, y, 5).lineWidth(1).strokeColor('#556273').stroke();
                doc.moveTo(x, y - 3).lineTo(x, y).lineTo(x + 3, y).stroke();
            }
            else {
                doc.moveTo(x - 4, y).lineTo(x + 4, y).lineWidth(1.5).strokeColor('#556273').stroke();
            }
        };
        const legend = () => {
            const entries = [['PRESENT', 'Présent', 85], ['ABSENT', 'Absent', 82], ['NOT_APPLICABLE', 'Hors effectif', 113], ['UNRECORDED', 'Non renseigné', 128], ['UPCOMING', 'À venir', 85], ['CANCELLED', 'Annulé', 75]];
            let x = margin;
            for (const [status, text, step] of entries) {
                marker(status, x + 5, doc.page.height - 52);
                label(text, x + 17, doc.page.height - 58, step - 17, 8);
                x += step;
            }
        };
        let pageIndex = 0;
        for (let groupIndex = 0; groupIndex < groups.length; groupIndex++) {
            const group = groups[groupIndex];
            const nameWidth = width - rateWidth - dateWidth * group.length;
            const pages = [[]];
            let usedHeight = 0;
            for (const player of players) {
                doc.font('Body').fontSize(10);
                const height = Math.max(32, doc.heightOfString(player.displayName, { width: nameWidth - 20 }) + 18);
                if (usedHeight + height > 340 && pages[pages.length - 1].length) {
                    pages.push([]);
                    usedHeight = 0;
                }
                pages[pages.length - 1].push({ player, height });
                usedHeight += height;
            }
            for (const pageRows of pages) {
                if (pageIndex++)
                    doc.addPage();
                label('Présences aux entraînements', margin, 30, width, 20, true);
                label(teamName, margin, 62, width, 13, true);
                label(`${monthTitle.charAt(0).toUpperCase() + monthTitle.slice(1)} | Saison ${report.season.label}`, margin, 85, width, 11);
                if (groups.length > 1)
                    label(`Dates - volet ${groupIndex + 1}/${groups.length}`, margin, 108, width, 9);
                const headerY = 136;
                doc.rect(margin, headerY, width, 30).fill('#E9F1EC');
                label('Joueur', margin + 10, headerY + 8, nameWidth - 20, 10, true);
                group.forEach((t, i) => label(new Intl.DateTimeFormat('fr-FR', { timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit' }).format(new Date(t.date)), margin + nameWidth + i * dateWidth, headerY + 8, dateWidth, 10, true, 'center'));
                label('Présence', margin + width - rateWidth, headerY + 8, rateWidth, 9, true, 'center');
                if (!trainings.length)
                    label('Aucun entraînement ce mois-ci.', margin + 10, 180, width - 20, 11);
                else if (!report.players.length)
                    label('Aucun joueur dans l’effectif actuel.', margin + 10, 180, width - 20, 11);
                else {
                    let rowY = headerY + 30;
                    pageRows.forEach(({ player: p, height: rowHeight }, i) => {
                        const y = rowY;
                        rowY += rowHeight;
                        if (i % 2 === 1)
                            doc.rect(margin, y, width, rowHeight).fill('#F5F7F6');
                        doc.font('Body').fontSize(10).fillColor('#203129').text(p.displayName, margin + 10, y + 9, { width: nameWidth - 20 });
                        const byTraining = new Map(p.attendances.map(a => [a.trainingId, a.status]));
                        group.forEach((t, j) => { const status = byTraining.get(t.id); const x = margin + nameWidth + j * dateWidth + dateWidth / 2; if (status)
                            marker(status, x, y + 16);
                        else
                            label('?', x - 8, y + 9, 16, 10, false, 'center'); });
                        const rate = p.months.find(m => m.month === month)?.summary.attendanceRate;
                        label(rate === null || rate === undefined ? '—' : `${new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 1 }).format(rate)} %`, margin + width - rateWidth, y + 10, rateWidth, 10, true, 'center');
                    });
                }
                legend();
            }
        }
        const range = doc.bufferedPageRange();
        for (let i = 0; i < range.count; i++) {
            doc.switchToPage(i);
            label(`${i + 1} / ${range.count}`, doc.page.width - 90, doc.page.height - 28, 54, 8, false, 'right');
        }
        doc.end();
    });
}
