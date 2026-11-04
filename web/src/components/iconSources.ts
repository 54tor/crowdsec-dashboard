import appsSvg from '@material-symbols/svg-400/outlined/apps.svg?raw'
import barChartSvg from '@material-symbols/svg-400/outlined/bar_chart.svg?raw'
import checkSvg from '@material-symbols/svg-400/outlined/check.svg?raw'
import checkCircleSvg from '@material-symbols/svg-400/outlined/check_circle.svg?raw'
import checklistSvg from '@material-symbols/svg-400/outlined/checklist.svg?raw'
import chevronLeftSvg from '@material-symbols/svg-400/outlined/chevron_left.svg?raw'
import chevronRightSvg from '@material-symbols/svg-400/outlined/chevron_right.svg?raw'
import closeSvg from '@material-symbols/svg-400/outlined/close.svg?raw'
import contentCopySvg from '@material-symbols/svg-400/outlined/content_copy.svg?raw'
import contrastSvg from '@material-symbols/svg-400/outlined/contrast.svg?raw'
import darkModeSvg from '@material-symbols/svg-400/outlined/dark_mode.svg?raw'
import densityMediumSvg from '@material-symbols/svg-400/outlined/density_medium.svg?raw'
import densitySmallSvg from '@material-symbols/svg-400/outlined/density_small.svg?raw'
import dnsSvg from '@material-symbols/svg-400/outlined/dns.svg?raw'
import errorSvg from '@material-symbols/svg-400/outlined/error.svg?raw'
import favoriteSvg from '@material-symbols/svg-400/outlined/favorite.svg?raw'
import filterListSvg from '@material-symbols/svg-400/outlined/filter_list.svg?raw'
import gavelSvg from '@material-symbols/svg-400/outlined/gavel.svg?raw'
import groupSvg from '@material-symbols/svg-400/outlined/group.svg?raw'
import inboxSvg from '@material-symbols/svg-400/outlined/inbox.svg?raw'
import infoSvg from '@material-symbols/svg-400/outlined/info.svg?raw'
import keySvg from '@material-symbols/svg-400/outlined/key.svg?raw'
import lanSvg from '@material-symbols/svg-400/outlined/lan.svg?raw'
import lightModeSvg from '@material-symbols/svg-400/outlined/light_mode.svg?raw'
import lockSvg from '@material-symbols/svg-400/outlined/lock.svg?raw'
import logoutSvg from '@material-symbols/svg-400/outlined/logout.svg?raw'
import moreHorizSvg from '@material-symbols/svg-400/outlined/more_horiz.svg?raw'
import progressActivitySvg from '@material-symbols/svg-400/outlined/progress_activity.svg?raw'
import shieldSvg from '@material-symbols/svg-400/outlined/shield.svg?raw'
import swapHorizSvg from '@material-symbols/svg-400/outlined/swap_horiz.svg?raw'
import syncSvg from '@material-symbols/svg-400/outlined/sync.svg?raw'
import translateSvg from '@material-symbols/svg-400/outlined/translate.svg?raw'
import tuneSvg from '@material-symbols/svg-400/outlined/tune.svg?raw'
import warningSvg from '@material-symbols/svg-400/outlined/warning.svg?raw'

export type IconName =
  | 'apps'
  | 'bar_chart'
  | 'check'
  | 'check_circle'
  | 'checklist'
  | 'chevron_left'
  | 'chevron_right'
  | 'close'
  | 'content_copy'
  | 'contrast'
  | 'dark_mode'
  | 'density_medium'
  | 'density_small'
  | 'dns'
  | 'error'
  | 'favorite'
  | 'filter_list'
  | 'gavel'
  | 'group'
  | 'inbox'
  | 'info'
  | 'key'
  | 'lan'
  | 'light_mode'
  | 'lock'
  | 'logout'
  | 'more_horiz'
  | 'progress_activity'
  | 'shield'
  | 'swap_horiz'
  | 'sync'
  | 'translate'
  | 'tune'
  | 'warning'

export const ICON_SOURCES: Record<IconName, string> = {
  apps: appsSvg,
  bar_chart: barChartSvg,
  check: checkSvg,
  check_circle: checkCircleSvg,
  checklist: checklistSvg,
  chevron_left: chevronLeftSvg,
  chevron_right: chevronRightSvg,
  close: closeSvg,
  content_copy: contentCopySvg,
  contrast: contrastSvg,
  dark_mode: darkModeSvg,
  density_medium: densityMediumSvg,
  density_small: densitySmallSvg,
  dns: dnsSvg,
  error: errorSvg,
  favorite: favoriteSvg,
  filter_list: filterListSvg,
  gavel: gavelSvg,
  group: groupSvg,
  inbox: inboxSvg,
  info: infoSvg,
  key: keySvg,
  lan: lanSvg,
  light_mode: lightModeSvg,
  lock: lockSvg,
  logout: logoutSvg,
  more_horiz: moreHorizSvg,
  progress_activity: progressActivitySvg,
  shield: shieldSvg,
  swap_horiz: swapHorizSvg,
  sync: syncSvg,
  translate: translateSvg,
  tune: tuneSvg,
  warning: warningSvg,
}
